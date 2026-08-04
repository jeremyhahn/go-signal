package postgres

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNew_EmptyDSN_ReturnsError(t *testing.T) {
	_, err := New(context.Background(), Config{})
	if err == nil {
		t.Fatal("expected error for empty DSN")
	}
}

func TestNew_BadDSN_ReturnsError(t *testing.T) {
	_, err := New(context.Background(), Config{DSN: "::not a dsn::"})
	if err == nil {
		t.Fatal("expected parse error")
	}
}

// TestNew_UnreachableHost exercises the Ping failure path: the pool is created
// successfully (DSN parses OK) but the Ping fails because no server listens
// on the given address.
func TestNew_UnreachableHost_PingFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := New(ctx, Config{
		DSN:            "postgres://signal:signal@127.0.0.1:19999/signal?sslmode=disable",
		ConnectTimeout: time.Second,
	})
	if err == nil {
		t.Fatal("expected error for unreachable host, got nil")
	}
}

func TestNew_AppliesAllOverrides(t *testing.T) {
	c := newTestClient(t)
	stat := c.Pool().Stat()
	if stat.MaxConns() <= 0 {
		t.Fatalf("MaxConns should be positive, got %d", stat.MaxConns())
	}
}

func TestNew_OverrideKnobs_Honored(t *testing.T) {
	dsn := envOrSkip(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := New(ctx, Config{
		DSN:             dsn,
		MaxConns:        7,
		MinConns:        1,
		MaxConnLifetime: time.Hour,
		MaxConnIdleTime: 30 * time.Minute,
		ConnectTimeout:  3 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()
	if got := c.Pool().Config().MaxConns; got != 7 {
		t.Fatalf("MaxConns: got %d want 7", got)
	}
}

func TestClient_Close_Idempotent(t *testing.T) {
	c := newTestClient(t)
	c.Close()
	c.Close() // must not panic
}

func TestWithTx_CommitsOnNilError(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	err := c.WithTx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `CREATE TEMP TABLE tmp_with_tx (n INT)`)
		return err
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}
}

func TestWithTx_RollsBackOnError(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	sentinel := errors.New("rollback please")
	err := c.WithTx(ctx, func(tx pgx.Tx) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
}

func TestWithTx_CapturesBeginError(t *testing.T) {
	c := newTestClient(t)
	c.Close() // close pool so Begin fails
	err := c.WithTx(context.Background(), func(tx pgx.Tx) error { return nil })
	if err == nil {
		t.Fatal("expected begin error after Close")
	}
}

func TestIsUniqueViolation(t *testing.T) {
	if IsUniqueViolation(nil) {
		t.Error("nil should not be unique violation")
	}
	if IsUniqueViolation(errors.New("plain")) {
		t.Error("non-pg should not match")
	}
	if !IsUniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Error("23505 should match")
	}
	if IsUniqueViolation(&pgconn.PgError{Code: "23503"}) {
		t.Error("23503 should not match unique")
	}
}

func TestIsForeignKeyViolation(t *testing.T) {
	if IsForeignKeyViolation(nil) {
		t.Error("nil")
	}
	if !IsForeignKeyViolation(&pgconn.PgError{Code: "23503"}) {
		t.Error("23503 should match")
	}
	if IsForeignKeyViolation(&pgconn.PgError{Code: "23505"}) {
		t.Error("23505 should not match")
	}
}

func TestIsCheckViolation(t *testing.T) {
	if IsCheckViolation(nil) {
		t.Error("nil")
	}
	if !IsCheckViolation(&pgconn.PgError{Code: "23514"}) {
		t.Error("23514 should match")
	}
	if IsCheckViolation(&pgconn.PgError{Code: "23505"}) {
		t.Error("23505 should not match")
	}
}

func TestIsSerializationFailure(t *testing.T) {
	if IsSerializationFailure(nil) {
		t.Error("nil")
	}
	if !IsSerializationFailure(&pgconn.PgError{Code: "40001"}) {
		t.Error("40001 should match")
	}
	if IsSerializationFailure(&pgconn.PgError{Code: "23505"}) {
		t.Error("23505 should not match")
	}
}

func TestIsNotFound(t *testing.T) {
	if IsNotFound(nil) {
		t.Error("nil")
	}
	if !IsNotFound(ErrNotFound) {
		t.Error("ErrNotFound should match")
	}
	if !IsNotFound(pgx.ErrNoRows) {
		t.Error("pgx.ErrNoRows should match")
	}
	wrapped := errors.New("outer: " + ErrNotFound.Error())
	if IsNotFound(wrapped) {
		// merely sharing the message isn't enough; only errors.Is matches
		t.Error("string-equal-but-not-wrapped must not match")
	}
}

// envOrSkip returns the test DSN or skips. Mirrors newTestClient's skip
// behavior for tests that build Client themselves.
func envOrSkip(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(testPostgresEnv)
	if dsn == "" {
		t.Skipf("%s not set; skipping", testPostgresEnv)
	}
	return dsn
}
