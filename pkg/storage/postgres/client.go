package postgres

import (
	"context"
	"errors"
	"log/slog"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a row that was expected to exist is absent.
// Domain stores wrap this in their own typed not-found errors before
// returning to callers.
var ErrNotFound = errors.New("postgres: not found")

// Querier is the subset of pgx that domain stores depend on. Both
// *pgxpool.Pool and pgx.Tx satisfy this, so a store written against
// Querier works inside or outside a transaction.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	SendBatch(ctx context.Context, b *pgx.Batch) pgx.BatchResults
}

// Compile-time checks that the implementations we hand out satisfy Querier.
var (
	_ Querier = (*pgxpool.Pool)(nil)
	_ Querier = (pgx.Tx)(nil)
)

// Config configures the Postgres client. DSN is a libpq-style connection
// string (postgres://user:pass@host:port/db?sslmode=...).
type Config struct {
	DSN string

	// MaxConns caps the connection pool. Zero means pgx default (~num CPUs).
	MaxConns int32
	// MinConns keeps idle connections warm. Zero means pgx default.
	MinConns int32
	// MaxConnLifetime recycles connections older than this. Zero means default.
	MaxConnLifetime time.Duration
	// MaxConnIdleTime closes idle connections older than this. Zero means default.
	MaxConnIdleTime time.Duration
	// ConnectTimeout caps each connection-establishment attempt.
	ConnectTimeout time.Duration

	// Logger is used for migration progress and pool-level events. nil falls
	// back to slog.Default().
	Logger *slog.Logger
}

// Client wraps a pgx connection pool and the embedded migrations runner.
// It is the single entry point that domain stores depend on.
type Client struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

// New connects to Postgres, verifies the connection, and returns a Client
// ready for use. Callers must Close when done.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.DSN == "" {
		return nil, errors.New("postgres: DSN is required")
	}
	pcfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres: parse DSN", err)
	}
	if cfg.MaxConns > 0 {
		pcfg.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		pcfg.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLifetime > 0 {
		pcfg.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.MaxConnIdleTime > 0 {
		pcfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	}
	if cfg.ConnectTimeout > 0 {
		pcfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}

	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres: connect", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres: ping", err)
	}
	return &Client{pool: pool, log: log}, nil
}

// Pool returns the underlying connection pool. Domain stores accept Querier
// rather than the concrete pool so they can run in a transaction; this
// accessor is for code that genuinely needs the pool (close, stats).
func (c *Client) Pool() *pgxpool.Pool { return c.pool }

// Close releases the connection pool. Safe to call multiple times.
func (c *Client) Close() {
	if c.pool != nil {
		c.pool.Close()
	}
}

// WithTx runs fn inside a transaction. The transaction is rolled back if fn
// returns an error and committed otherwise. This is the path domain stores
// use for the multi-statement operations Java uses TransactWriteItems for
// (e.g., account create with phone-number constraint, change-number).
func (c *Client) WithTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := c.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: begin tx", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// IsUniqueViolation reports whether err is a Postgres unique-constraint
// violation (SQLSTATE 23505). Used by domain stores to map ON CONFLICT
// scenarios to typed already-exists errors.
func IsUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// IsForeignKeyViolation reports whether err is a Postgres foreign-key
// violation (SQLSTATE 23503).
func IsForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

// IsCheckViolation reports whether err is a Postgres check-constraint
// violation (SQLSTATE 23514).
func IsCheckViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23514"
}

// IsSerializationFailure reports whether err is a serialization failure
// (SQLSTATE 40001), which is retryable for transactions running at higher
// isolation levels.
func IsSerializationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40001"
}

// IsNotFound reports whether err indicates a missing row, either via the
// package-level ErrNotFound or pgx.ErrNoRows.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, pgx.ErrNoRows)
}
