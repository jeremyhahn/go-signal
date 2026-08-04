package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/devices"
)

func newProvisioningSession(code, accountUUID string, expiresAt time.Time) *devices.ProvisioningSession {
	return &devices.ProvisioningSession{
		Code:      code,
		UUID:      accountUUID,
		ExpiresAt: expiresAt,
	}
}

func TestProvisioningStore_StoreGet_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewProvisioningStore(c.Pool())
	ctx := context.Background()

	code := uuid.NewString()
	accountUUID := uuid.NewString()
	exp := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Microsecond)

	sess := newProvisioningSession(code, accountUUID, exp)
	if err := s.StoreSession(ctx, sess); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}

	got, err := s.GetSession(ctx, code)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Code != code {
		t.Errorf("Code: got %q, want %q", got.Code, code)
	}
	if got.UUID != accountUUID {
		t.Errorf("UUID: got %q, want %q", got.UUID, accountUUID)
	}
	if !got.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt: got %v, want %v", got.ExpiresAt, exp)
	}
}

// StoreSession must overwrite an existing session stored under the same code,
// matching the qrdb "store replaces" contract.
func TestProvisioningStore_StoreSession_OverwritesExisting(t *testing.T) {
	c := newTestClient(t)
	s := NewProvisioningStore(c.Pool())
	ctx := context.Background()

	code := uuid.NewString()
	originalUUID := uuid.NewString()
	replacedUUID := uuid.NewString()
	exp := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Microsecond)

	if err := s.StoreSession(ctx, newProvisioningSession(code, originalUUID, exp)); err != nil {
		t.Fatalf("StoreSession (first): %v", err)
	}
	if err := s.StoreSession(ctx, newProvisioningSession(code, replacedUUID, exp)); err != nil {
		t.Fatalf("StoreSession (overwrite): %v", err)
	}

	got, err := s.GetSession(ctx, code)
	if err != nil {
		t.Fatalf("GetSession after overwrite: %v", err)
	}
	if got.UUID != replacedUUID {
		t.Errorf("UUID after overwrite: got %q, want %q", got.UUID, replacedUUID)
	}
}

func TestProvisioningStore_StoreSession_NilSessionRejected(t *testing.T) {
	c := newTestClient(t)
	s := NewProvisioningStore(c.Pool())

	err := s.StoreSession(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil session, got nil")
	}
}

func TestProvisioningStore_StoreSession_EmptyCodeRejected(t *testing.T) {
	c := newTestClient(t)
	s := NewProvisioningStore(c.Pool())

	err := s.StoreSession(context.Background(), &devices.ProvisioningSession{
		UUID:      uuid.NewString(),
		ExpiresAt: time.Now().Add(time.Minute),
	})
	if err == nil {
		t.Fatal("expected error for empty code, got nil")
	}
}

func TestProvisioningStore_GetSession_Missing_ReturnsInvalidCode(t *testing.T) {
	c := newTestClient(t)
	s := NewProvisioningStore(c.Pool())

	_, err := s.GetSession(context.Background(), "does-not-exist")
	var ice *devices.InvalidProvisioningCodeError
	if !errors.As(err, &ice) {
		t.Fatalf("expected InvalidProvisioningCodeError, got %T: %v", err, err)
	}
}

func TestProvisioningStore_DeleteSession_RemovesSession(t *testing.T) {
	c := newTestClient(t)
	s := NewProvisioningStore(c.Pool())
	ctx := context.Background()

	code := uuid.NewString()
	if err := s.StoreSession(ctx, newProvisioningSession(code, uuid.NewString(),
		time.Now().Add(time.Minute))); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
	if err := s.DeleteSession(ctx, code); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	_, err := s.GetSession(ctx, code)
	var ice *devices.InvalidProvisioningCodeError
	if !errors.As(err, &ice) {
		t.Fatalf("expected InvalidProvisioningCodeError after delete, got %T: %v", err, err)
	}
}

// DeleteSession on a missing code must be idempotent — it must not return an
// error. This matches the qrdb implementation.
func TestProvisioningStore_DeleteSession_Idempotent(t *testing.T) {
	c := newTestClient(t)
	s := NewProvisioningStore(c.Pool())

	if err := s.DeleteSession(context.Background(), "nonexistent-code"); err != nil {
		t.Fatalf("DeleteSession on missing code: want nil, got %v", err)
	}
}

func TestProvisioningStore_StoreSession_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewProvisioningStore(c.Pool())
	c.Close()

	sess := newProvisioningSession(uuid.NewString(), uuid.NewString(), time.Now().Add(time.Minute))
	err := s.StoreSession(context.Background(), sess)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestProvisioningStore_DeleteSession_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewProvisioningStore(c.Pool())
	c.Close()

	err := s.DeleteSession(context.Background(), "some-code")
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestProvisioningStore_GetSession_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewProvisioningStore(c.Pool())
	c.Close()

	_, err := s.GetSession(context.Background(), "some-code")
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}
