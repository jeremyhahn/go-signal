package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/registration/recoverypassword"
)

func TestNewMemoryRecoveryPasswordStore(t *testing.T) {
	s := NewMemoryRecoveryPasswordStore()
	if s == nil {
		t.Fatal("expected non-nil store")
		return
	}
	if s.entries == nil {
		t.Fatal("expected entries map to be initialized")
	}
}

func TestRecoveryPassword_PutGetRoundTrip(t *testing.T) {
	s := NewMemoryRecoveryPasswordStore()
	ctx := context.Background()

	hash := &recoverypassword.SaltedTokenHash{Hash: "2.deadbeef", Salt: "abcdef"}
	if err := s.Put(ctx, "pni-1", hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get(ctx, "pni-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Hash != hash.Hash || got.Salt != hash.Salt {
		t.Fatalf("Get returned %+v; want %+v", got, hash)
	}

	// Mutating the returned copy must not affect storage.
	got.Hash = "tampered"
	again, err := s.Get(ctx, "pni-1")
	if err != nil {
		t.Fatalf("Get again: %v", err)
	}
	if again.Hash == "tampered" {
		t.Fatal("expected stored hash to be insulated from caller mutation")
	}
}

func TestRecoveryPassword_PutNilHashRejected(t *testing.T) {
	s := NewMemoryRecoveryPasswordStore()
	ctx := context.Background()

	if err := s.Put(ctx, "pni", nil, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("expected error for nil hash")
	} else if _, ok := err.(*recoverypassword.InvalidArgumentError); !ok {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
}

func TestRecoveryPassword_GetNotFound(t *testing.T) {
	s := NewMemoryRecoveryPasswordStore()
	_, err := s.Get(context.Background(), "absent")
	var nf *recoverypassword.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError, got %T", err)
	}
}

func TestRecoveryPassword_GetExpiredEvicts(t *testing.T) {
	s := NewMemoryRecoveryPasswordStore()
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })

	hash := &recoverypassword.SaltedTokenHash{Hash: "2.x", Salt: "y"}
	if err := s.Put(ctx, "pni-e", hash, now.Add(time.Minute)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Advance past expiration.
	s.SetClock(func() time.Time { return now.Add(time.Hour) })

	if _, err := s.Get(ctx, "pni-e"); err == nil {
		t.Fatal("expected NotFoundError for expired entry")
	}

	// The entry should be evicted; rolling the clock back must NOT bring it
	// back, proving lazy eviction occurred.
	s.SetClock(func() time.Time { return now })
	if _, err := s.Get(ctx, "pni-e"); err == nil {
		t.Fatal("expected expired row to remain evicted")
	}
}

// TestSetClockNil_NoOp ensures passing nil to SetClock leaves the original
// clock in place rather than panicking.
func TestSetClockNil_NoOp(t *testing.T) {
	s := NewMemoryRecoveryPasswordStore()
	s.SetClock(nil)
	if s.now == nil {
		t.Fatal("expected default clock to remain after SetClock(nil)")
	}
}

func TestRecoveryPassword_DeleteIdempotent(t *testing.T) {
	s := NewMemoryRecoveryPasswordStore()
	ctx := context.Background()

	if err := s.Delete(ctx, "ghost"); err != nil {
		t.Fatalf("Delete on missing: %v", err)
	}

	if err := s.Put(ctx, "pni-d", &recoverypassword.SaltedTokenHash{Hash: "2.d", Salt: "s"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, "pni-d"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "pni-d"); err == nil {
		t.Fatal("expected NotFoundError after Delete")
	}
}

func TestRecoveryPassword_PutReplaces(t *testing.T) {
	s := NewMemoryRecoveryPasswordStore()
	ctx := context.Background()

	first := &recoverypassword.SaltedTokenHash{Hash: "2.first", Salt: "salt-a"}
	if err := s.Put(ctx, "pni-r", first, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put first: %v", err)
	}

	second := &recoverypassword.SaltedTokenHash{Hash: "2.second", Salt: "salt-b"}
	if err := s.Put(ctx, "pni-r", second, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put second: %v", err)
	}

	got, err := s.Get(ctx, "pni-r")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Hash != "2.second" {
		t.Fatalf("expected replacement hash, got %q", got.Hash)
	}
}

func TestRecoveryPassword_Concurrent(t *testing.T) {
	s := NewMemoryRecoveryPasswordStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			pni := "pni-" + string(rune('A'+i))
			_ = s.Put(ctx, pni, &recoverypassword.SaltedTokenHash{Hash: "2.x", Salt: "s"}, time.Now().Add(time.Hour))
		}(i)
		go func(i int) {
			defer wg.Done()
			pni := "pni-" + string(rune('A'+i))
			_, _ = s.Get(ctx, pni)
		}(i)
	}
	wg.Wait()
}

// TestRecoveryPassword_InterfaceSatisfaction guarantees the concrete type
// continues to satisfy the package interface as the interface evolves.
func TestRecoveryPassword_InterfaceSatisfaction(t *testing.T) {
	var _ recoverypassword.Store = (*MemoryRecoveryPasswordStore)(nil)
}
