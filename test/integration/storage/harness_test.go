// Package storage_test provides cross-backend contract tests for every domain
// storage interface in go-signal. The suite verifies that memory, qrdb, and
// postgres implementations satisfy identical behavioral contracts so semantic
// drift between backends is caught before it reaches production.
//
// Run without postgres (memory + qrdb only):
//
//	go test ./test/integration/storage/...
//
// Run with all three backends (postgres must be running):
//
//	TEST_POSTGRES_URL='postgres://signal:signal@127.0.0.1:55432/signal?sslmode=disable' \
//	  go test -count=1 -tags fido2 ./test/integration/storage/...
package storage_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
)

// testPostgresEnv is the environment variable that enables postgres-backed
// contract tests. When unset, all postgres sub-tests skip cleanly.
const testPostgresEnv = "TEST_POSTGRES_URL"

// testLockKey is the same advisory-lock key that pkg/storage/postgres uses
// in its testhelpers. Both packages serialize against this key so that
// running `go test ./pkg/storage/postgres/... ./test/integration/storage/...`
// can't interleave their TRUNCATEs and seed sequences against the shared
// test database. Keep in sync with pkg/storage/postgres/testhelpers_test.go.
const testLockKey int64 = 0x607551147A1A2A2D

// postgresClient returns a migrated, truncated postgres *Client, or skips
// the calling test if TEST_POSTGRES_URL is unset. It holds a Postgres
// session-level advisory lock for the duration of the test, serializing
// against any other suite using the same DB. Callers must not close the
// returned client directly — a t.Cleanup is registered automatically.
func postgresClient(t *testing.T) *postgres.Client {
	t.Helper()
	dsn := os.Getenv(testPostgresEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping postgres integration tests", testPostgresEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := postgres.New(ctx, postgres.Config{
		DSN:            dsn,
		ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("postgres connect: %v", err)
	}
	t.Cleanup(c.Close)

	if err := c.Migrate(ctx); err != nil {
		t.Fatalf("postgres migrate: %v", err)
	}

	// Lock on a dedicated connection (separate from the pool) so tests
	// that close the pool can't deadlock on this connection's release.
	lockConn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("postgres connect lock conn: %v", err)
	}
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock($1)`, testLockKey); err != nil {
		_ = lockConn.Close(ctx)
		t.Fatalf("postgres acquire test lock: %v", err)
	}
	t.Cleanup(func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer releaseCancel()
		_ = lockConn.Close(releaseCtx)
	})

	if err := truncatePostgres(ctx, c); err != nil {
		t.Fatalf("postgres truncate: %v", err)
	}
	return c
}

// truncatePostgres empties all domain tables so each top-level test starts
// from a clean database. The list matches the one used by the postgres package
// tests themselves.
func truncatePostgres(ctx context.Context, c *postgres.Client) error {
	const sql = `TRUNCATE TABLE
		scheduled_jobs,
		remote_config,
		spam_reports,
		storage_items,
		storage_manifests,
		fido2_sessions,
		fido2_credentials,
		verification_sessions,
		profiles,
		messages,
		groups,
		username_links,
		usernames_reserved,
		usernames_confirmed,
		provisioning_sessions,
		prekeys_kem_lastresort,
		prekeys_ec_signed,
		prekeys_kem_onetime,
		prekeys_ec_onetime,
		accounts
	RESTART IDENTITY CASCADE`
	_, err := c.Pool().Exec(ctx, sql)
	return err
}
