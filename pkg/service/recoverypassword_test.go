package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	storagememory "github.com/jeremyhahn/go-signal/pkg/storage/memory"

	recoverypassword "github.com/jeremyhahn/go-signal/pkg/registration/recoverypassword"
)

func TestNewRecoveryPasswordService_InterfaceSatisfaction(t *testing.T) {
	var _ RecoveryPasswordService = (*recoveryPasswordService)(nil)
}

func newTestRecoveryPasswordService() RecoveryPasswordService {
	store := storagememory.NewMemoryRecoveryPasswordStore()
	mgr := recoverypassword.NewManager(store, 24*time.Hour, slog.Default())
	return NewRecoveryPasswordService(mgr)
}

func TestRecoveryPasswordService_StoreAndVerify_Match(t *testing.T) {
	svc := newTestRecoveryPasswordService()
	ctx := context.Background()

	if err := svc.Store(ctx, "pni-rp-01", []byte("my-secret")); err != nil {
		t.Fatalf("Store: unexpected error: %v", err)
	}

	ok, err := svc.Verify(ctx, "pni-rp-01", []byte("my-secret"))
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if !ok {
		t.Error("Verify: expected true for matching password")
	}
}

func TestRecoveryPasswordService_Verify_WrongPassword(t *testing.T) {
	svc := newTestRecoveryPasswordService()
	ctx := context.Background()

	if err := svc.Store(ctx, "pni-rp-02", []byte("correct")); err != nil {
		t.Fatalf("Store: %v", err)
	}

	ok, err := svc.Verify(ctx, "pni-rp-02", []byte("wrong"))
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if ok {
		t.Error("Verify: expected false for wrong password")
	}
}

func TestRecoveryPasswordService_Verify_NotFound(t *testing.T) {
	svc := newTestRecoveryPasswordService()
	ok, err := svc.Verify(context.Background(), "pni-not-found", []byte("pw"))
	if err != nil {
		t.Fatalf("Verify: unexpected error for missing entry: %v", err)
	}
	if ok {
		t.Error("Verify: expected false when no entry exists")
	}
}
