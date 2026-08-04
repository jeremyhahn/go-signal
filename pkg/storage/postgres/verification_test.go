package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/verification"
)

func newVerificationSession(id, number string, expiresAt time.Time) *verification.VerificationSession {
	return &verification.VerificationSession{
		ID:                   id,
		Number:               number,
		Verified:             false,
		Attempts:             0,
		AllowedToRequestCode: true,
		CreatedAt:            time.Now().UTC().Truncate(time.Microsecond),
		ExpiresAt:            expiresAt.UTC().Truncate(time.Microsecond),
	}
}

func TestVerificationStore_Create_Get_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	ctx := context.Background()

	id := uuid.NewString()
	exp := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Microsecond)
	want := newVerificationSession(id, "+15551234567", exp)

	if err := s.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != id {
		t.Errorf("ID: got %q, want %q", got.ID, id)
	}
	if got.Number != "+15551234567" {
		t.Errorf("Number: got %q, want %q", got.Number, "+15551234567")
	}
	if !got.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt: got %v, want %v", got.ExpiresAt, exp)
	}
}

func TestVerificationStore_Create_NilSessionRejected(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())

	if err := s.Create(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil session, got nil")
	}
}

func TestVerificationStore_Create_EmptyIDRejected(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())

	sess := newVerificationSession("", "+15551234567", time.Now().Add(time.Minute))
	if err := s.Create(context.Background(), sess); err == nil {
		t.Fatal("expected error for empty ID, got nil")
	}
}

func TestVerificationStore_Create_DuplicateID_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	ctx := context.Background()

	id := uuid.NewString()
	sess := newVerificationSession(id, "+15551234567", time.Now().Add(time.Minute))

	if err := s.Create(ctx, sess); err != nil {
		t.Fatalf("Create (first): %v", err)
	}
	err := s.Create(ctx, sess)
	if err == nil {
		t.Fatal("expected error on duplicate create, got nil")
	}
}

func TestVerificationStore_Get_Missing_ReturnsSessionNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())

	_, err := s.Get(context.Background(), "missing-session-id")
	var snfe *verification.SessionNotFoundError
	if !errors.As(err, &snfe) {
		t.Fatalf("expected SessionNotFoundError, got %T: %v", err, err)
	}
}

func TestVerificationStore_Update_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	ctx := context.Background()

	id := uuid.NewString()
	sess := newVerificationSession(id, "+15551234567", time.Now().Add(10*time.Minute))
	if err := s.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	sess.Verified = true
	sess.Attempts = 2
	if err := s.Update(ctx, sess); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if !got.Verified {
		t.Error("expected Verified=true after update")
	}
	if got.Attempts != 2 {
		t.Errorf("Attempts: got %d, want 2", got.Attempts)
	}
}

func TestVerificationStore_Update_Missing_ReturnsSessionNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())

	sess := newVerificationSession(uuid.NewString(), "+15551234567", time.Now().Add(time.Minute))
	err := s.Update(context.Background(), sess)
	var snfe *verification.SessionNotFoundError
	if !errors.As(err, &snfe) {
		t.Fatalf("expected SessionNotFoundError, got %T: %v", err, err)
	}
}

func TestVerificationStore_Delete_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	ctx := context.Background()

	id := uuid.NewString()
	if err := s.Create(ctx, newVerificationSession(id, "+15551234567", time.Now().Add(time.Minute))); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Delete(ctx, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := s.Get(ctx, id)
	var snfe *verification.SessionNotFoundError
	if !errors.As(err, &snfe) {
		t.Fatalf("expected SessionNotFoundError after delete, got %T: %v", err, err)
	}
}

func TestVerificationStore_Delete_Missing_ReturnsSessionNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())

	err := s.Delete(context.Background(), "no-such-session")
	var snfe *verification.SessionNotFoundError
	if !errors.As(err, &snfe) {
		t.Fatalf("expected SessionNotFoundError, got %T: %v", err, err)
	}
}

func TestVerificationStore_Count(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	ctx := context.Background()

	n, err := s.Count(ctx)
	if err != nil {
		t.Fatalf("Count (empty): %v", err)
	}
	if n != 0 {
		t.Fatalf("Count (empty): got %d, want 0", n)
	}

	for i := range 3 {
		sess := newVerificationSession(uuid.NewString(), "+1555000000"+string(rune('0'+i)),
			time.Now().Add(time.Minute))
		if err := s.Create(ctx, sess); err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
	}

	n, err = s.Count(ctx)
	if err != nil {
		t.Fatalf("Count (after inserts): %v", err)
	}
	if n != 3 {
		t.Fatalf("Count (after inserts): got %d, want 3", n)
	}
}

// TestVerificationStore_DeleteExpired verifies that only expired sessions are
// removed and unexpired sessions survive.
func TestVerificationStore_DeleteExpired_RemovesOnlyExpired(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	ctx := context.Background()

	expiredID := uuid.NewString()
	liveID := uuid.NewString()

	// Insert a session already expired (expires_at in the past).
	expired := newVerificationSession(expiredID, "+15550000001", time.Now().Add(-time.Minute))
	if err := s.Create(ctx, expired); err != nil {
		t.Fatalf("Create expired: %v", err)
	}

	// Insert a session that is still valid.
	live := newVerificationSession(liveID, "+15550000002", time.Now().Add(10*time.Minute))
	if err := s.Create(ctx, live); err != nil {
		t.Fatalf("Create live: %v", err)
	}

	if err := s.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	// Expired session must be gone.
	_, err := s.Get(ctx, expiredID)
	var snfe *verification.SessionNotFoundError
	if !errors.As(err, &snfe) {
		t.Fatalf("expired session still present: got %T: %v", err, err)
	}

	// Live session must survive.
	if _, err := s.Get(ctx, liveID); err != nil {
		t.Fatalf("live session unexpectedly removed: %v", err)
	}
}

func TestVerificationStore_Update_NilSession_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())

	err := s.Update(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil session update, got nil")
	}
}

// TestVerificationStore_DeleteExpired_NoExpiredRows verifies DeleteExpired
// on a store containing only non-expired sessions is a no-op.
func TestVerificationStore_DeleteExpired_NoExpiredRows_IsNoOp(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	ctx := context.Background()

	liveID := uuid.NewString()
	live := newVerificationSession(liveID, "+15550000099", time.Now().Add(10*time.Minute))
	if err := s.Create(ctx, live); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	// The live session must survive.
	if _, err := s.Get(ctx, liveID); err != nil {
		t.Fatalf("live session unexpectedly removed: %v", err)
	}
}

func TestVerificationStore_DeleteExpired_EmptyStore_NoError(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())

	if err := s.DeleteExpired(context.Background()); err != nil {
		t.Fatalf("DeleteExpired on empty store: %v", err)
	}
}

func TestVerificationStore_Update_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	c.Close()

	sess := newVerificationSession(uuid.NewString(), "+15551234567", time.Now().Add(time.Minute))
	err := s.Update(context.Background(), sess)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestVerificationStore_Delete_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	c.Close()

	err := s.Delete(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *verification.SessionNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not SessionNotFoundError")
	}
}

func TestVerificationStore_Create_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	c.Close()

	sess := newVerificationSession(uuid.NewString(), "+15551234567", time.Now().Add(time.Minute))
	err := s.Create(context.Background(), sess)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestVerificationStore_Count_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	c.Close()

	_, err := s.Count(context.Background())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestVerificationStore_DeleteExpired_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	c.Close()

	err := s.DeleteExpired(context.Background())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestVerificationStore_Get_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	c.Close()

	_, err := s.Get(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

// TestVerificationStore_Get_CorruptedData_UnmarshalError exercises the
// json.Unmarshal error branch in Get (verification.go:88-90). A row is
// inserted via raw SQL with a data value whose createdAt field is not a valid
// RFC3339 string, so json.Unmarshal fails even though the row exists.
func TestVerificationStore_Get_CorruptedData_UnmarshalError(t *testing.T) {
	c := newTestClient(t)
	s := NewVerificationSessionStore(c.Pool())
	ctx := context.Background()

	id := uuid.NewString()
	exp := time.Now().Add(time.Hour)

	// Insert valid JSONB but with an unparseable time value for createdAt.
	// Postgres accepts any valid JSON in the JSONB column; Go's json.Unmarshal
	// will fail when it tries to parse "NOT-A-TIME" as time.Time.
	_, err := c.Pool().Exec(ctx,
		`INSERT INTO verification_sessions (id, data, expires_at, created_at)
		 VALUES ($1, $2::jsonb, $3, NOW())`,
		id,
		`{"id":"`+id+`","number":"+1555","createdAt":"NOT-A-TIME"}`,
		exp,
	)
	if err != nil {
		t.Fatalf("raw insert: %v", err)
	}

	_, err = s.Get(ctx, id)
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
	var snfe *verification.SessionNotFoundError
	if errors.As(err, &snfe) {
		t.Fatal("expected unmarshal error, not SessionNotFoundError")
	}
}
