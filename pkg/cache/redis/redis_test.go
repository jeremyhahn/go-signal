package redis

import (
	"testing"

	redisv9 "github.com/redis/go-redis/v9"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// Most redis operations require a live Redis server to test meaningfully.
// Those are exercised in the integration test suite. The tests here cover
// constructor validation and the wrapper's configuration propagation,
// which must work regardless of connectivity.

func TestNew_ValidURL(t *testing.T) {
	t.Parallel()
	c, err := New(t.Context(), Config{URL: "redis://localhost:6379/0"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c == nil || c.rdb == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNew_InvalidURL(t *testing.T) {
	t.Parallel()
	if _, err := New(t.Context(), Config{URL: "not a url"}); err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

func TestNew_PasswordOverride(t *testing.T) {
	t.Parallel()
	c, err := New(t.Context(), Config{
		URL:      "redis://localhost:6379/0",
		Password: secrets.MustNewSecureString(t.Context(), "secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.rdb.Options().Password != "secret" {
		t.Fatalf("password not applied: %q", c.rdb.Options().Password)
	}
}

// A nil SecureString is the common case (no AUTH configured) and must not
// panic or clobber a password already carried in the connection URL.
func TestNew_NilPasswordKeepsURLCredential(t *testing.T) {
	t.Parallel()
	c, err := New(t.Context(), Config{URL: "redis://:urlpass@localhost:6379/0"})
	if err != nil {
		t.Fatal(err)
	}
	if c.rdb.Options().Password != "urlpass" {
		t.Fatalf("URL password not preserved: %q", c.rdb.Options().Password)
	}
}

// A destroyed SecureString must behave like an absent one rather than
// applying an empty AUTH password.
func TestNew_DestroyedPasswordKeepsURLCredential(t *testing.T) {
	t.Parallel()
	pw := secrets.MustNewSecureString(t.Context(), "secret")
	pw.Destroy()
	c, err := New(t.Context(), Config{URL: "redis://:urlpass@localhost:6379/0", Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	if c.rdb.Options().Password != "urlpass" {
		t.Fatalf("URL password not preserved: %q", c.rdb.Options().Password)
	}
}

func TestNew_DBOverride(t *testing.T) {
	t.Parallel()
	c, err := New(t.Context(), Config{URL: "redis://localhost:6379/0", DB: 3})
	if err != nil {
		t.Fatal(err)
	}
	if c.rdb.Options().DB != 3 {
		t.Fatalf("DB not applied: %d", c.rdb.Options().DB)
	}
}

func TestNewFromClient_Wraps(t *testing.T) {
	t.Parallel()
	rdb := redisv9.NewClient(&redisv9.Options{Addr: "localhost:6379"})
	defer func() { _ = rdb.Close() }()
	c := NewFromClient(rdb)
	if c == nil || c.rdb != rdb {
		t.Fatal("NewFromClient did not wrap the provided client")
	}
}
