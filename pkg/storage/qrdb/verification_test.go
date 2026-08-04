package qrdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/verification"
)

func newVerificationSession(id string, expiresAt time.Time) *verification.VerificationSession {
	return &verification.VerificationSession{
		ID:        id,
		Number:    "+15551234567",
		CreatedAt: time.Now().Add(-time.Minute),
		ExpiresAt: expiresAt,
	}
}

func TestVerificationSessionStore_Create_And_Get(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewVerificationSessionStore(NewFakeKVStore())

	sess := newVerificationSession("sess-1", time.Now().Add(time.Hour))
	if err := s.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(ctx, "sess-1")
	if err != nil || got.Number != "+15551234567" {
		t.Fatalf("Get: err=%v got=%+v", err, got)
	}
}

func TestVerificationSessionStore_Create_Duplicate_Rejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewVerificationSessionStore(NewFakeKVStore())

	sess := newVerificationSession("sess-1", time.Now().Add(time.Hour))
	if err := s.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, sess); err == nil {
		t.Fatal("expected duplicate Create to fail")
	}
}

func TestVerificationSessionStore_Create_Invalid(t *testing.T) {
	t.Parallel()
	s := NewVerificationSessionStore(NewFakeKVStore())
	if err := s.Create(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil session")
	}
	if err := s.Create(context.Background(), &verification.VerificationSession{}); err == nil {
		t.Fatal("expected error for empty session ID")
	}
}

func TestVerificationSessionStore_Get_Missing(t *testing.T) {
	t.Parallel()
	s := NewVerificationSessionStore(NewFakeKVStore())
	_, err := s.Get(context.Background(), "missing")
	var snfe *verification.SessionNotFoundError
	if !errors.As(err, &snfe) {
		t.Fatalf("expected SessionNotFoundError, got %T: %v", err, err)
	}
}

func TestVerificationSessionStore_Update_And_Count(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewVerificationSessionStore(NewFakeKVStore())

	sess := newVerificationSession("sess-1", time.Now().Add(time.Hour))
	if err := s.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}

	sess.Attempts = 3
	if err := s.Update(ctx, sess); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, _ := s.Get(ctx, "sess-1")
	if got.Attempts != 3 {
		t.Fatalf("Update did not persist: %+v", got)
	}

	n, err := s.Count(ctx)
	if err != nil || n != 1 {
		t.Fatalf("Count: n=%d err=%v", n, err)
	}
}

func TestVerificationSessionStore_Update_Missing_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := NewVerificationSessionStore(NewFakeKVStore())
	sess := newVerificationSession("sess-1", time.Now().Add(time.Hour))
	err := s.Update(context.Background(), sess)
	var snfe *verification.SessionNotFoundError
	if !errors.As(err, &snfe) {
		t.Fatalf("expected SessionNotFoundError, got %T: %v", err, err)
	}
}

func TestVerificationSessionStore_Update_NilRejected(t *testing.T) {
	t.Parallel()
	s := NewVerificationSessionStore(NewFakeKVStore())
	if err := s.Update(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil session")
	}
}

func TestVerificationSessionStore_Delete_Success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewVerificationSessionStore(NewFakeKVStore())

	sess := newVerificationSession("sess-1", time.Now().Add(time.Hour))
	if err := s.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "sess-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := s.Get(ctx, "sess-1")
	var snfe *verification.SessionNotFoundError
	if !errors.As(err, &snfe) {
		t.Fatal("expected session to be absent after Delete")
	}
}

func TestVerificationSessionStore_Delete_Missing(t *testing.T) {
	t.Parallel()
	s := NewVerificationSessionStore(NewFakeKVStore())
	err := s.Delete(context.Background(), "missing")
	var snfe *verification.SessionNotFoundError
	if !errors.As(err, &snfe) {
		t.Fatalf("expected SessionNotFoundError, got %T: %v", err, err)
	}
}

func TestVerificationSessionStore_DeleteExpired_RemovesOnlyExpired(t *testing.T) {
	// No t.Parallel: this test mutates the package-level timeNow, which would
	// race with any concurrent test that swaps it (see verification.go).
	ctx := context.Background()
	s := NewVerificationSessionStore(NewFakeKVStore())

	now := time.Now()
	// Swap timeNow so the test is deterministic.
	origNow := timeNow
	defer func() { timeNow = origNow }()
	timeNow = func() time.Time { return now }

	expired := newVerificationSession("expired", now.Add(-time.Hour))
	alive := newVerificationSession("alive", now.Add(time.Hour))

	if err := s.Create(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, alive); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	if _, err := s.Get(ctx, "expired"); err == nil {
		t.Fatal("expected expired session to be removed")
	}
	if _, err := s.Get(ctx, "alive"); err != nil {
		t.Fatalf("alive session should be retained: %v", err)
	}
}

func TestVerificationSessionStore_Count_Empty(t *testing.T) {
	t.Parallel()
	s := NewVerificationSessionStore(NewFakeKVStore())
	n, err := s.Count(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("Count empty: n=%d err=%v", n, err)
	}
}
