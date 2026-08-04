package qrdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/devices"
)

func newSession(code string) *devices.ProvisioningSession {
	return &devices.ProvisioningSession{
		Code:      code,
		UUID:      "account-uuid-" + code,
		ExpiresAt: time.Date(2026, 4, 22, 1, 0, 0, 0, time.UTC),
	}
}

func TestProvisioningStore_StoreAndGet_Roundtrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewProvisioningStore(NewFakeKVStore())

	want := newSession("ABC123")
	if err := s.StoreSession(ctx, want); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}

	got, err := s.GetSession(ctx, "ABC123")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Code != want.Code || got.UUID != want.UUID || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("roundtrip mismatch: got %+v, want %+v", got, want)
	}
}

func TestProvisioningStore_Store_NilSession_Rejected(t *testing.T) {
	t.Parallel()
	s := NewProvisioningStore(NewFakeKVStore())

	if err := s.StoreSession(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil session")
	}
}

func TestProvisioningStore_Store_EmptyCode_Rejected(t *testing.T) {
	t.Parallel()
	s := NewProvisioningStore(NewFakeKVStore())

	if err := s.StoreSession(context.Background(), &devices.ProvisioningSession{}); err == nil {
		t.Fatal("expected error for empty code")
	}
}

func TestProvisioningStore_Get_Missing_ReturnsInvalidProvisioningCodeError(t *testing.T) {
	t.Parallel()
	s := NewProvisioningStore(NewFakeKVStore())

	_, err := s.GetSession(context.Background(), "missing")
	var ipce *devices.InvalidProvisioningCodeError
	if !errors.As(err, &ipce) {
		t.Fatalf("expected InvalidProvisioningCodeError, got %T: %v", err, err)
	}
	if ipce.Code != "missing" {
		t.Fatalf("wrong code in error: %s", ipce.Code)
	}
}

func TestProvisioningStore_Store_Overwrites_ExistingSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewProvisioningStore(NewFakeKVStore())

	original := newSession("ABC")
	if err := s.StoreSession(ctx, original); err != nil {
		t.Fatal(err)
	}

	replacement := &devices.ProvisioningSession{
		Code:      "ABC",
		UUID:      "different-account",
		ExpiresAt: original.ExpiresAt.Add(time.Hour),
	}
	if err := s.StoreSession(ctx, replacement); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetSession(ctx, "ABC")
	if err != nil {
		t.Fatal(err)
	}
	if got.UUID != "different-account" {
		t.Fatalf("expected overwrite, got %+v", got)
	}
}

func TestProvisioningStore_Delete_Existing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewProvisioningStore(NewFakeKVStore())

	if err := s.StoreSession(ctx, newSession("ABC")); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, "ABC"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	_, err := s.GetSession(ctx, "ABC")
	var ipce *devices.InvalidProvisioningCodeError
	if !errors.As(err, &ipce) {
		t.Fatalf("expected session to be absent, got: %v", err)
	}
}

func TestProvisioningStore_Delete_Missing_Idempotent(t *testing.T) {
	t.Parallel()
	s := NewProvisioningStore(NewFakeKVStore())

	// Deleting a code that was never stored must not error.
	if err := s.DeleteSession(context.Background(), "never-existed"); err != nil {
		t.Fatalf("DeleteSession should be idempotent: %v", err)
	}
}
