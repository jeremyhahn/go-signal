package postgres

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// testPostgresEnv is the environment variable that points tests at a live
// Postgres instance. When unset, all postgres-backed tests in this package
// skip — they are integration tests that require a running database.
//
// In the project devcontainer this is preset to:
//
//	postgres://signal:signal@postgres:5432/signal?sslmode=disable
const testPostgresEnv = "TEST_POSTGRES_URL"

// testLockKey is the Postgres advisory-lock key used to serialize tests
// across every package that shares the same test database. Without this,
// `go test ./pkg/storage/postgres/... ./test/integration/storage/...` runs
// the two packages in parallel and their TRUNCATE / seed sequences
// interleave, producing FK-violation noise on a shared DB. The integration
// harness uses the same key. Do not change it.
const testLockKey int64 = 0x607551147A1A2A2D

// newTestClient returns a migrated *Client pointed at the test database, or
// skips the test if TEST_POSTGRES_URL is unset. It acquires a Postgres
// session-level advisory lock for the duration of the test, then truncates
// the public schema. Tests can be written assuming exclusive access to the
// database.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	dsn := os.Getenv(testPostgresEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping postgres integration test", testPostgresEnv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := New(ctx, Config{DSN: dsn, ConnectTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("postgres connect: %v", err)
	}
	t.Cleanup(c.Close)

	if err := c.Migrate(ctx); err != nil {
		t.Fatalf("postgres migrate: %v", err)
	}

	// Hold a session-level advisory lock across the whole test. The lock
	// is acquired on a *dedicated* pgx.Conn — separate from the test's
	// pool — so tests that intentionally close the pool (Pool_Closed
	// coverage cases) do not deadlock waiting for this connection to
	// return. Cleanup closes the conn, which releases the session lock
	// automatically.
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

	if err := truncateAll(ctx, c); err != nil {
		t.Fatalf("postgres truncate: %v", err)
	}
	return c
}

// seedAccount inserts a minimal accounts row to satisfy FK constraints in
// tables that reference accounts(aci). The account is cleaned up when the
// test database is truncated between tests.
func seedAccount(t *testing.T, c *Client, aci string) {
	t.Helper()
	ctx := context.Background()
	a := &accounts.Account{
		UUID:      aci,
		PNI:       uuid.NewString(),
		Number:    "+1555" + aci[:7], // unique enough within a single test
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Version:   0,
	}
	s := NewAccountStore(c.Pool())
	if err := s.Create(ctx, a); err != nil {
		t.Fatalf("seedAccount: %v", err)
	}
}

// noTxQuerier wraps a Querier by embedding only the Querier interface, which
// means it exposes exactly the four Querier methods and does NOT expose
// BeginTx. This lets tests exercise code paths that check for the beginner
// interface (withTxQuerier in keys.go) and the txQuerier interface (Set in
// profiles.go) without a real transaction.
type noTxQuerier struct{ Querier }

// truncateAll empties every domain table to give each test a clean slate.
// The list is hand-maintained so it stays explicit when new tables are
// added to a migration. CASCADE clears FK-dependent rows in one statement.
func truncateAll(ctx context.Context, c *Client) error {
	const sql = `TRUNCATE TABLE
		remote_config,
		call_quality_surveys,
		registration_recovery_passwords,
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
	_, err := c.pool.Exec(ctx, sql)
	return err
}
