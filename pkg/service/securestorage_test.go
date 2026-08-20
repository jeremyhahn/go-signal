package service_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	"github.com/jeremyhahn/go-signal/pkg/service"
	storagememory "github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

// newTestSecureStorageService builds a SecureStorageService backed by an
// in-memory manifest store so delegation tests exercise the real code paths.
func newTestSecureStorageService() service.SecureStorageService {
	mgr := newTestSecureStorageManager()
	return service.NewSecureStorageService(mgr)
}

func newTestSecureStorageManager() *securestorage.SecureStorageManager {
	mgr := securestorage.NewSecureStorageManager(slog.Default())
	mgr.SetManifestStore(storagememory.NewMemoryManifestStore())
	return mgr
}

// --------------------------------------------------------------------------
// NewSecureStorageService
// --------------------------------------------------------------------------

func TestNewSecureStorageService_InterfaceSatisfaction(t *testing.T) {
	var _ service.SecureStorageService = service.NewSecureStorageService(
		securestorage.NewSecureStorageManager(slog.Default()),
	)
}

func TestNewSecureStorageService_NotNil(t *testing.T) {
	svc := newTestSecureStorageService()
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

// --------------------------------------------------------------------------
// StorageEnabled
// --------------------------------------------------------------------------

func TestSecureStorageService_StorageEnabled_False(t *testing.T) {
	// Manager without a store → StorageEnabled returns false.
	mgr := securestorage.NewSecureStorageManager(slog.Default())
	svc := service.NewSecureStorageService(mgr)
	if svc.StorageEnabled() {
		t.Error("expected StorageEnabled false when no store configured")
	}
}

func TestSecureStorageService_StorageEnabled_True(t *testing.T) {
	svc := newTestSecureStorageService()
	if !svc.StorageEnabled() {
		t.Error("expected StorageEnabled true when memory store is configured")
	}
}

// --------------------------------------------------------------------------
// GetAuth
// --------------------------------------------------------------------------

func TestSecureStorageService_GetAuth_ReturnsCredentials(t *testing.T) {
	svc := newTestSecureStorageService()
	creds, err := svc.GetAuth(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
	if creds.Username != "user-1" {
		t.Errorf("expected username %q, got %q", "user-1", creds.Username)
	}
	if creds.Password.Plaintext() == "" {
		t.Error("expected non-empty password")
	}
}

func TestSecureStorageService_GetAuth_DifferentUUIDs(t *testing.T) {
	svc := newTestSecureStorageService()
	c1, _ := svc.GetAuth(context.Background(), "uuid-a")
	c2, _ := svc.GetAuth(context.Background(), "uuid-b")
	if c1.Username == c2.Username {
		t.Error("expected different usernames for different UUIDs")
	}
}

// --------------------------------------------------------------------------
// GetManifest
// --------------------------------------------------------------------------

func TestSecureStorageService_GetManifest_NilWhenNoManifest(t *testing.T) {
	svc := newTestSecureStorageService()
	m, err := svc.GetManifest(context.Background(), "acct-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Errorf("expected nil manifest before any write, got %+v", m)
	}
}

func TestSecureStorageService_GetManifest_ReturnsStoredManifest(t *testing.T) {
	svc := newTestSecureStorageService()
	ctx := context.Background()
	const acct = "acct-2"

	manifest := &securestorage.StorageManifest{Version: 5, Value: []byte("test")}
	if _, err := svc.Write(ctx, acct, manifest, nil, nil, false); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := svc.GetManifest(ctx, acct)
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if got == nil || got.Version != 5 {
		t.Errorf("expected manifest version 5, got %+v", got)
	}
}

// --------------------------------------------------------------------------
// Write
// --------------------------------------------------------------------------

func TestSecureStorageService_Write_Success(t *testing.T) {
	svc := newTestSecureStorageService()
	ctx := context.Background()

	conflict, err := svc.Write(ctx, "acct-3",
		&securestorage.StorageManifest{Version: 1},
		[]*securestorage.StorageItem{{Key: []byte("k"), Value: []byte("v")}},
		nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conflict != nil {
		t.Errorf("expected no conflict, got %+v", conflict)
	}
}

func TestSecureStorageService_Write_VersionConflictReturnsCurrentManifest(t *testing.T) {
	svc := newTestSecureStorageService()
	ctx := context.Background()
	const acct = "acct-4"

	// First write at version 3.
	if _, err := svc.Write(ctx, acct,
		&securestorage.StorageManifest{Version: 3}, nil, nil, false); err != nil {
		t.Fatalf("first write: %v", err)
	}

	// Second write at same version 3 → conflict.
	conflict, err := svc.Write(ctx, acct,
		&securestorage.StorageManifest{Version: 3}, nil, nil, false)
	if err != nil {
		t.Fatalf("conflicting write: %v", err)
	}
	if conflict == nil {
		t.Fatal("expected conflict manifest, got nil")
	}
	if conflict.Version != 3 {
		t.Errorf("expected conflict at version 3, got %d", conflict.Version)
	}
}

func TestSecureStorageService_Write_NilManifestError(t *testing.T) {
	svc := newTestSecureStorageService()
	if _, err := svc.Write(context.Background(), "acct-5", nil, nil, nil, false); err == nil {
		t.Fatal("expected error for nil manifest")
	}
}

// --------------------------------------------------------------------------
// Read
// --------------------------------------------------------------------------

func TestSecureStorageService_Read_ReturnsStoredItems(t *testing.T) {
	svc := newTestSecureStorageService()
	ctx := context.Background()
	const acct = "acct-6"

	items := []*securestorage.StorageItem{
		{Key: []byte("k1"), Value: []byte("v1")},
		{Key: []byte("k2"), Value: []byte("v2")},
	}
	if _, err := svc.Write(ctx, acct,
		&securestorage.StorageManifest{Version: 1}, items, nil, false); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := svc.Read(ctx, acct, [][]byte{[]byte("k1"), []byte("missing")})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 item (missing key omitted), got %d", len(got))
	}
}

func TestSecureStorageService_Read_EmptyKeys(t *testing.T) {
	svc := newTestSecureStorageService()
	got, err := svc.Read(context.Background(), "acct-7", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result for nil keys, got %d items", len(got))
	}
}
