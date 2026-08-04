package workers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/cache/memory"
)

func TestCacheLeaser_AcquireAndRelease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	l := NewCacheLeaser(memory.New(), "test:")

	if err := l.Acquire(ctx, "worker-a", time.Minute); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := l.Release(ctx, "worker-a"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// After release, a second Acquire must succeed.
	if err := l.Acquire(ctx, "worker-a", time.Minute); err != nil {
		t.Fatalf("reacquire after release: %v", err)
	}
}

func TestCacheLeaser_Acquire_WhenHeld_ReturnsLeaderElectionFailed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cache := memory.New()
	first := NewCacheLeaser(cache, "test:")
	second := NewCacheLeaser(cache, "test:")

	if err := first.Acquire(ctx, "worker-b", time.Minute); err != nil {
		t.Fatal(err)
	}
	err := second.Acquire(ctx, "worker-b", time.Minute)
	if !errors.Is(err, ErrLeaderElectionFailed) {
		t.Fatalf("expected ErrLeaderElectionFailed, got %v", err)
	}
}

func TestCacheLeaser_Release_WithoutAcquire_IsNoOp(t *testing.T) {
	t.Parallel()
	l := NewCacheLeaser(memory.New(), "")
	if err := l.Release(context.Background(), "never-acquired"); err != nil {
		t.Fatalf("Release should be safe when nothing was acquired: %v", err)
	}
}

func TestCacheLeaser_DefaultPrefix(t *testing.T) {
	t.Parallel()
	l := NewCacheLeaser(memory.New(), "")
	if l.prefix != "workers:lease:" {
		t.Fatalf("expected default prefix, got %q", l.prefix)
	}
}

func TestCacheLeaser_Acquire_TokenRecorded(t *testing.T) {
	t.Parallel()
	l := NewCacheLeaser(memory.New(), "test:")
	if err := l.Acquire(context.Background(), "w", time.Minute); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tokens["test:w"]; !ok {
		t.Fatal("expected token to be recorded under prefixed key")
	}
}

func TestCacheLeaser_Stale_TTL_Expired_AllowsReacquisition(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cache := memory.New()
	first := NewCacheLeaser(cache, "test:")

	if err := first.Acquire(ctx, "w", 10*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	// A different leaser can now acquire the same key.
	second := NewCacheLeaser(cache, "test:")
	if err := second.Acquire(ctx, "w", time.Minute); err != nil {
		t.Fatalf("expected reacquisition after TTL, got %v", err)
	}
}
