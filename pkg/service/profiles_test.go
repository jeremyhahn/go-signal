package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/profiles"
)

// TestNewProfileService_InterfaceSatisfaction verifies the concrete type
// satisfies the ProfileService interface at compile time.
func TestNewProfileService_InterfaceSatisfaction(t *testing.T) {
	var _ ProfileService = (*profileService)(nil)
}

func newTestProfileService() ProfileService {
	store := newMockProfileStore()
	mgr := profiles.NewProfilesManager(store)
	return NewProfileService(mgr)
}

func TestProfileService_Set_Success(t *testing.T) {
	svc := newTestProfileService()
	p := &profiles.Profile{
		UUID:    "uuid-p01",
		Version: "v1",
		Name:    []byte("Alice"),
	}

	if err := svc.Set(context.Background(), p); err != nil {
		t.Fatalf("Set: unexpected error: %v", err)
	}
}

func TestProfileService_Set_StoreError(t *testing.T) {
	store := newMockProfileStore()
	store.setErr = errors.New("write failure")
	mgr := profiles.NewProfilesManager(store)
	svc := NewProfileService(mgr)

	err := svc.Set(context.Background(), &profiles.Profile{UUID: "uuid-p99", Version: "v1"})
	if err == nil {
		t.Fatal("Set: expected error from store")
	}
}

func TestProfileService_Get_Success(t *testing.T) {
	svc := newTestProfileService()
	p := &profiles.Profile{UUID: "uuid-p02", Version: "v1", Name: []byte("Bob")}
	if err := svc.Set(context.Background(), p); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := svc.Get(context.Background(), "uuid-p02", "v1")
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if got.UUID != "uuid-p02" {
		t.Errorf("Get: expected uuid-p02, got %q", got.UUID)
	}
}

func TestProfileService_Get_NotFound(t *testing.T) {
	svc := newTestProfileService()
	_, err := svc.Get(context.Background(), "missing-uuid", "v1")
	if err == nil {
		t.Fatal("Get: expected error for missing profile")
	}
}

func TestProfileService_Get_StoreError(t *testing.T) {
	store := newMockProfileStore()
	store.getErr = errors.New("read failure")
	mgr := profiles.NewProfilesManager(store)
	svc := NewProfileService(mgr)

	_, err := svc.Get(context.Background(), "uuid-p03", "v1")
	if err == nil {
		t.Fatal("Get: expected error from store")
	}
}

func TestProfileService_GetLatest_Success(t *testing.T) {
	svc := newTestProfileService()
	// Insert two versions; GetLatest should return the lexicographically last.
	if err := svc.Set(context.Background(), &profiles.Profile{UUID: "uuid-p04", Version: "v1", Name: []byte("Charlie")}); err != nil {
		t.Fatalf("Set v1: %v", err)
	}
	if err := svc.Set(context.Background(), &profiles.Profile{UUID: "uuid-p04", Version: "v2", Name: []byte("Charlie2")}); err != nil {
		t.Fatalf("Set v2: %v", err)
	}

	got, err := svc.GetLatest(context.Background(), "uuid-p04")
	if err != nil {
		t.Fatalf("GetLatest: unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("GetLatest: expected a profile")
	}
}

func TestProfileService_GetLatest_NotFound(t *testing.T) {
	svc := newTestProfileService()
	_, err := svc.GetLatest(context.Background(), "missing-uuid")
	if err == nil {
		t.Fatal("GetLatest: expected error for missing profile")
	}
}

func TestProfileService_Delete_Success(t *testing.T) {
	svc := newTestProfileService()
	p := &profiles.Profile{UUID: "uuid-p05", Version: "v1"}
	if err := svc.Set(context.Background(), p); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := svc.Delete(context.Background(), "uuid-p05"); err != nil {
		t.Fatalf("Delete: unexpected error: %v", err)
	}

	_, err := svc.Get(context.Background(), "uuid-p05", "v1")
	if err == nil {
		t.Fatal("Delete: profile still accessible after deletion")
	}
}

func TestProfileService_Delete_NotFound(t *testing.T) {
	svc := newTestProfileService()
	// Deleting a non-existent profile is idempotent — the mock returns nil.
	if err := svc.Delete(context.Background(), "nonexistent"); err != nil {
		t.Fatalf("Delete: unexpected error for nonexistent profile: %v", err)
	}
}
