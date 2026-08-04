package postgres

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationLockKey is a constant 64-bit value used with pg_advisory_lock to
// serialize concurrent migrators. Any constant works; this one was generated
// once and is part of the on-disk contract for go-signal's schema. Do not
// change it.
const migrationLockKey int64 = 0x607551147A1A1B1C

// migration is a parsed pair of up/down SQL files for a single version.
type migration struct {
	version int
	name    string
	up      string
	down    string
}

// Migrate brings the connected database to the latest schema version. It is
// safe to call concurrently from multiple processes — a Postgres advisory
// lock serializes execution. A schema_migrations bookkeeping table records
// applied versions; only versions strictly greater than the recorded
// maximum are applied.
func (c *Client) Migrate(ctx context.Context) error {
	migrations, err := loadMigrations()
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: load migrations", err)
	}
	if len(migrations) == 0 {
		return nil
	}

	conn, err := c.pool.Acquire(ctx)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: acquire conn", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: acquire migration lock", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, migrationLockKey)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    BIGINT       PRIMARY KEY,
			name       TEXT         NOT NULL,
			applied_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
		)`); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: ensure schema_migrations", err)
	}

	var current int
	if err := conn.QueryRow(ctx,
		`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`,
	).Scan(&current); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: read current version", err)
	}

	applied := 0
	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		c.log.Info("applying postgres migration",
			"version", m.version, "name", m.name)
		if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.up); err != nil {
				return signalerrors.Wrap(signalerrors.ErrInternal, "execute up", err)
			}
			_, err := tx.Exec(ctx,
				`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`,
				m.version, m.name)
			return err
		}); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: migration "+strconv.Itoa(m.version)+" ("+m.name+")", err)
		}
		applied++
	}
	if applied > 0 {
		c.log.Info("postgres migrations applied", "count", applied)
	}
	return nil
}

// loadMigrations reads the embedded migrations directory and pairs up/down
// files by version. File naming: "NNNN_name.up.sql" / "NNNN_name.down.sql".
func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}
	byVersion := map[int]*migration{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		base := strings.TrimSuffix(name, ".sql")
		dir := ""
		switch {
		case strings.HasSuffix(base, ".up"):
			dir = "up"
			base = strings.TrimSuffix(base, ".up")
		case strings.HasSuffix(base, ".down"):
			dir = "down"
			base = strings.TrimSuffix(base, ".down")
		default:
			return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "postgres: migration "+strconv.Quote(name)+" must end .up.sql or .down.sql")
		}
		parts := strings.SplitN(base, "_", 2)
		if len(parts) != 2 {
			return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "postgres: migration "+strconv.Quote(name)+" must be NNNN_name")
		}
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInvalidArgument, "postgres: migration "+strconv.Quote(name)+": bad version", err)
		}
		m, ok := byVersion[v]
		if !ok {
			m = &migration{version: v, name: parts[1]}
			byVersion[v] = m
		}
		body, err := fs.ReadFile(migrationsFS, "migrations/"+name)
		if err != nil {
			return nil, err
		}
		switch dir {
		case "up":
			m.up = string(body)
		case "down":
			m.down = string(body)
		}
	}
	out := make([]migration, 0, len(byVersion))
	for _, m := range byVersion {
		if m.up == "" {
			return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "postgres: migration "+strconv.Itoa(m.version)+" ("+m.name+") missing .up.sql")
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// ErrNoDownMigration is returned by Rollback when the requested version has
// no .down.sql counterpart.
var ErrNoDownMigration = errors.New("postgres: migration has no down")
