package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/registration/recoverypassword"
)

func TestRecoveryPasswords_PutGetRoundTrip(t *testing.T) {
	c := newTestClient(t)
	s := NewRecoveryPasswordStore(c)
	ctx := context.Background()

	pni := uuid.NewString()
	hash := &recoverypassword.SaltedTokenHash{Hash: "2.deadbeefcafe", Salt: "abcdef0123456789abcdef0123456789"}
	if err := s.Put(ctx, pni, hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.Get(ctx, pni)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Hash != hash.Hash || got.Salt != hash.Salt {
		t.Fatalf("Get returned %+v; want %+v", got, hash)
	}
}

func TestRecoveryPasswords_GetMissing(t *testing.T) {
	c := newTestClient(t)
	s := NewRecoveryPasswordStore(c)

	_, err := s.Get(context.Background(), uuid.NewString())
	var nf *recoverypassword.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError, got %T", err)
	}
}

func TestRecoveryPasswords_PutReplacesExisting(t *testing.T) {
	c := newTestClient(t)
	s := NewRecoveryPasswordStore(c)
	ctx := context.Background()

	pni := uuid.NewString()
	first := &recoverypassword.SaltedTokenHash{Hash: "2.first", Salt: "salt-a"}
	if err := s.Put(ctx, pni, first, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	second := &recoverypassword.SaltedTokenHash{Hash: "2.second", Salt: "salt-b"}
	if err := s.Put(ctx, pni, second, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put second: %v", err)
	}

	got, err := s.Get(ctx, pni)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Hash != "2.second" {
		t.Fatalf("expected replacement hash, got %q", got.Hash)
	}
}

func TestRecoveryPasswords_GetExpiredEvicts(t *testing.T) {
	c := newTestClient(t)
	s := NewRecoveryPasswordStore(c)
	ctx := context.Background()

	pni := uuid.NewString()
	hash := &recoverypassword.SaltedTokenHash{Hash: "2.x", Salt: "y"}
	// Insert with an already-elapsed expires_at.
	if err := s.Put(ctx, pni, hash, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if _, err := s.Get(ctx, pni); err == nil {
		t.Fatal("expected NotFoundError for expired row")
	}

	// Confirm the row was deleted as a side effect.
	var count int
	if err := c.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM registration_recovery_passwords WHERE pni = $1`, pni,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected expired row to be deleted; got count=%d", count)
	}
}

func TestRecoveryPasswords_DeleteIdempotent(t *testing.T) {
	c := newTestClient(t)
	s := NewRecoveryPasswordStore(c)
	ctx := context.Background()

	if err := s.Delete(ctx, uuid.NewString()); err != nil {
		t.Fatalf("Delete missing: %v", err)
	}

	pni := uuid.NewString()
	if err := s.Put(ctx, pni,
		&recoverypassword.SaltedTokenHash{Hash: "2.d", Salt: "s"},
		time.Now().Add(time.Hour),
	); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, pni); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, pni); err == nil {
		t.Fatal("expected NotFoundError after Delete")
	}
}

func TestRecoveryPasswords_PutNilRejected(t *testing.T) {
	c := newTestClient(t)
	s := NewRecoveryPasswordStore(c)
	if err := s.Put(context.Background(), uuid.NewString(), nil, time.Now().Add(time.Hour)); err == nil {
		t.Fatal("expected error for nil hash")
	}
}

func TestRecoveryPasswords_SetClockOverridesNow(t *testing.T) {
	c := newTestClient(t)
	s := NewRecoveryPasswordStore(c)
	ctx := context.Background()

	pni := uuid.NewString()
	hash := &recoverypassword.SaltedTokenHash{Hash: "2.clk", Salt: "s"}
	if err := s.Put(ctx, pni, hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Inject a clock far in the future so the row is treated as expired even
	// though wall-clock has not elapsed.
	s.SetClock(func() time.Time { return time.Now().Add(48 * time.Hour) })
	if _, err := s.Get(ctx, pni); err == nil {
		t.Fatal("expected expired result with future clock")
	}
	// Setting nil clock leaves the override in place.
	s.SetClock(nil)
}
