package memory

import (
	"context"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/cache"
)

// These tests exercise the WRONGTYPE-style error branches for every
// operation family (string, zset, hash). The three types are mutually
// exclusive per key, so attempting an operation of the wrong kind must
// return an error rather than silently behaving incorrectly.

func TestWrongType_GetOnZSet(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.ZAdd(context.Background(), "k", cache.ScoredMember{Score: 1, Member: []byte("m")})
	_, err := c.Get(context.Background(), "k")
	if err == nil || !strings.Contains(err.Error(), "zset") {
		t.Fatalf("expected wrongType on Get against zset, got %v", err)
	}
}

func TestWrongType_GetOnHash(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.HSet(context.Background(), "k", "f", []byte("v"))
	_, err := c.Get(context.Background(), "k")
	if err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("expected wrongType on Get against hash, got %v", err)
	}
}

func TestWrongType_HSetOnString(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Set(context.Background(), "k", []byte("v"), 0)
	err := c.HSet(context.Background(), "k", "f", []byte("v"))
	if err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("expected wrongType, got %v", err)
	}
}

func TestWrongType_HGetOnString(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Set(context.Background(), "k", []byte("v"), 0)
	_, err := c.HGet(context.Background(), "k", "f")
	if err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("expected wrongType, got %v", err)
	}
}

func TestWrongType_HDelOnZSet(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.ZAdd(context.Background(), "k", cache.ScoredMember{Score: 1, Member: []byte("m")})
	err := c.HDel(context.Background(), "k", "f")
	if err == nil {
		t.Fatal("expected wrongType")
	}
}

func TestWrongType_HLenOnString(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Set(context.Background(), "k", []byte("v"), 0)
	_, err := c.HLen(context.Background(), "k")
	if err == nil {
		t.Fatal("expected wrongType")
	}
}

func TestWrongType_ZRemOnString(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Set(context.Background(), "k", []byte("v"), 0)
	err := c.ZRem(context.Background(), "k", []byte("m"))
	if err == nil {
		t.Fatal("expected wrongType")
	}
}

func TestWrongType_ZCardOnHash(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.HSet(context.Background(), "k", "f", []byte("v"))
	_, err := c.ZCard(context.Background(), "k")
	if err == nil {
		t.Fatal("expected wrongType")
	}
}

func TestWrongType_ZRangeOnString(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Set(context.Background(), "k", []byte("v"), 0)
	_, err := c.ZRange(context.Background(), "k", 0, -1)
	if err == nil {
		t.Fatal("expected wrongType")
	}
}

// ---- Expired-key transitions -----------------------------------------

func TestZAdd_AfterExpiration_FreshZSet(t *testing.T) {
	t.Parallel()
	c := New()
	// Seed with a short-TTL string.
	_ = c.Set(context.Background(), "k", []byte("v"), 1)
	// Wait past expiration — expired key should be reclaimed on next touch.
	for i := 0; i < 5 && func() bool {
		ok, _ := c.Exists(context.Background(), "k")
		return ok
	}(); i++ {
	}

	// After expiration, ZAdd at the same key must succeed as a new zset.
	err := c.ZAdd(context.Background(), "k", cache.ScoredMember{Score: 1, Member: []byte("m")})
	if err != nil {
		t.Fatalf("ZAdd on expired-string key should succeed as new zset: %v", err)
	}
}

// ---- Closed-client error paths --------------------------------------

func TestClosedClient_RejectsAllMutations(t *testing.T) {
	t.Parallel()
	c := New()
	_ = c.Close()

	ctx := context.Background()
	mutations := map[string]func() error{
		"Set":     func() error { return c.Set(ctx, "k", []byte("v"), 0) },
		"Del":     func() error { return c.Del(ctx, "k") },
		"Expire":  func() error { _, err := c.Expire(ctx, "k", 0); return err },
		"Incr":    func() error { _, err := c.Incr(ctx, "k"); return err },
		"IncrBy":  func() error { _, err := c.IncrBy(ctx, "k", 1); return err },
		"Lock":    func() error { return c.Lock(ctx, "k", "t", 0) },
		"Unlock":  func() error { return c.Unlock(ctx, "k", "t") },
		"ZAdd":    func() error { return c.ZAdd(ctx, "k", cache.ScoredMember{Score: 1, Member: []byte("m")}) },
		"ZRange":  func() error { _, err := c.ZRange(ctx, "k", 0, -1); return err },
		"ZRem":    func() error { return c.ZRem(ctx, "k", []byte("m")) },
		"ZCard":   func() error { _, err := c.ZCard(ctx, "k"); return err },
		"HSet":    func() error { return c.HSet(ctx, "k", "f", []byte("v")) },
		"HGet":    func() error { _, err := c.HGet(ctx, "k", "f"); return err },
		"HDel":    func() error { return c.HDel(ctx, "k", "f") },
		"HLen":    func() error { _, err := c.HLen(ctx, "k"); return err },
		"Publish": func() error { _, err := c.Publish(ctx, "ch", nil); return err },
	}
	for name, fn := range mutations {
		if err := fn(); err == nil {
			t.Errorf("%s on closed client should return an error", name)
		}
	}

	if _, err := c.Subscribe(ctx, "ch"); err == nil {
		t.Error("Subscribe on closed client should return an error")
	}
}
