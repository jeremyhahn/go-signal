package profiles

import (
	"context"
	"errors"
	"testing"
)

// mockProfileStore is a test double for ProfileStore.
type mockProfileStore struct {
	profiles map[string]map[string]*Profile // uuid -> version -> profile
	latest   map[string]string              // uuid -> latest version
	setErr   error
	getErr   error
	delErr   error
}

func newMockProfileStore() *mockProfileStore {
	return &mockProfileStore{
		profiles: make(map[string]map[string]*Profile),
		latest:   make(map[string]string),
	}
}

func (s *mockProfileStore) Set(_ context.Context, profile *Profile) error {
	if s.setErr != nil {
		return s.setErr
	}
	versions, exists := s.profiles[profile.UUID]
	if !exists {
		versions = make(map[string]*Profile)
		s.profiles[profile.UUID] = versions
	}
	clone := cloneProfile(profile)
	versions[profile.Version] = clone
	s.latest[profile.UUID] = profile.Version
	return nil
}

func (s *mockProfileStore) Get(_ context.Context, uuid string, version string) (*Profile, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	versions, exists := s.profiles[uuid]
	if !exists {
		return nil, &ProfileNotFoundError{UUID: uuid, Version: version}
	}
	p, exists := versions[version]
	if !exists {
		return nil, &ProfileNotFoundError{UUID: uuid, Version: version}
	}
	return cloneProfile(p), nil
}

func (s *mockProfileStore) GetLatest(_ context.Context, uuid string) (*Profile, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	ver, exists := s.latest[uuid]
	if !exists {
		return nil, &ProfileNotFoundError{UUID: uuid}
	}
	versions := s.profiles[uuid]
	p, exists := versions[ver]
	if !exists {
		return nil, &ProfileNotFoundError{UUID: uuid, Version: ver}
	}
	return cloneProfile(p), nil
}

func (s *mockProfileStore) Delete(_ context.Context, uuid string) error {
	if s.delErr != nil {
		return s.delErr
	}
	if _, exists := s.profiles[uuid]; !exists {
		return &ProfileNotFoundError{UUID: uuid}
	}
	delete(s.profiles, uuid)
	delete(s.latest, uuid)
	return nil
}

func cloneProfile(p *Profile) *Profile {
	return &Profile{
		UUID:           p.UUID,
		Version:        p.Version,
		Name:           cloneBytes(p.Name),
		About:          cloneBytes(p.About),
		AboutEmoji:     cloneBytes(p.AboutEmoji),
		Avatar:         p.Avatar,
		Commitment:     cloneBytes(p.Commitment),
		PaymentAddress: cloneBytes(p.PaymentAddress),
	}
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

func testProfile(uuid, version string) *Profile {
	return &Profile{
		UUID:           uuid,
		Version:        version,
		Name:           []byte("test-name"),
		About:          []byte("test-about"),
		AboutEmoji:     []byte("test-emoji"),
		Avatar:         "avatar-url",
		Commitment:     []byte("test-commitment"),
		PaymentAddress: []byte("test-payment"),
	}
}

// --- NewProfilesManager tests ---

func TestNewProfilesManager(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)
	if mgr == nil {
		t.Fatal("expected non-nil ProfilesManager")
	}
}

func TestNewProfilesManagerStoreAssigned(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)
	if mgr.store != store {
		t.Fatal("expected store to be assigned")
	}
}

// --- Set tests ---

func TestSet_Success(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	profile := testProfile("uuid-1", "v1")
	err := mgr.Set(context.Background(), profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify profile was stored.
	got, err := mgr.Get(context.Background(), "uuid-1", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-1" {
		t.Fatalf("expected UUID %q, got %q", "uuid-1", got.UUID)
	}
	if string(got.Name) != "test-name" {
		t.Fatalf("expected Name %q, got %q", "test-name", string(got.Name))
	}
}

func TestSet_OverwriteVersion(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	profile1 := testProfile("uuid-1", "v1")
	if err := mgr.Set(context.Background(), profile1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	profile2 := &Profile{
		UUID:    "uuid-1",
		Version: "v1",
		Name:    []byte("updated-name"),
	}
	if err := mgr.Set(context.Background(), profile2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := mgr.Get(context.Background(), "uuid-1", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got.Name) != "updated-name" {
		t.Fatalf("expected Name %q, got %q", "updated-name", string(got.Name))
	}
}

func TestSet_StoreError(t *testing.T) {
	store := newMockProfileStore()
	store.setErr = errors.New("store failure")
	mgr := NewProfilesManager(store)

	err := mgr.Set(context.Background(), testProfile("uuid-1", "v1"))
	if err == nil {
		t.Fatal("expected error when store fails")
	}
	if err.Error() != "store failure" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSet_MultipleVersions(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	if err := mgr.Set(context.Background(), testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mgr.Set(context.Background(), testProfile("uuid-1", "v2")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both versions should be retrievable.
	got1, err := mgr.Get(context.Background(), "uuid-1", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got1.Version != "v1" {
		t.Fatalf("expected version %q, got %q", "v1", got1.Version)
	}

	got2, err := mgr.Get(context.Background(), "uuid-1", "v2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2.Version != "v2" {
		t.Fatalf("expected version %q, got %q", "v2", got2.Version)
	}
}

// --- Get tests ---

func TestGet_Success(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	if err := mgr.Set(context.Background(), testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := mgr.Get(context.Background(), "uuid-1", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Avatar != "avatar-url" {
		t.Fatalf("expected Avatar %q, got %q", "avatar-url", got.Avatar)
	}
}

func TestGet_NotFound(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	_, err := mgr.Get(context.Background(), "nonexistent", "v1")
	if err == nil {
		t.Fatal("expected error for nonexistent profile")
	}

	var nf *ProfileNotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *ProfileNotFoundError, got %T", err)
	}
}

func TestGet_VersionNotFound(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	if err := mgr.Set(context.Background(), testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := mgr.Get(context.Background(), "uuid-1", "v999")
	if err == nil {
		t.Fatal("expected error for nonexistent version")
	}

	var nf *ProfileNotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *ProfileNotFoundError, got %T", err)
	}
}

func TestGet_StoreError(t *testing.T) {
	store := newMockProfileStore()
	store.getErr = errors.New("get failure")
	mgr := NewProfilesManager(store)

	_, err := mgr.Get(context.Background(), "uuid-1", "v1")
	if err == nil {
		t.Fatal("expected error when store fails")
	}
}

// --- GetLatest tests ---

func TestGetLatest_Success(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	if err := mgr.Set(context.Background(), testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p2 := testProfile("uuid-1", "v2")
	p2.Name = []byte("latest-name")
	if err := mgr.Set(context.Background(), p2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := mgr.GetLatest(context.Background(), "uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Version != "v2" {
		t.Fatalf("expected version %q, got %q", "v2", got.Version)
	}
	if string(got.Name) != "latest-name" {
		t.Fatalf("expected Name %q, got %q", "latest-name", string(got.Name))
	}
}

func TestGetLatest_NotFound(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	_, err := mgr.GetLatest(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent profile")
	}

	var nf *ProfileNotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *ProfileNotFoundError, got %T", err)
	}
}

func TestGetLatest_StoreError(t *testing.T) {
	store := newMockProfileStore()
	store.getErr = errors.New("get failure")
	mgr := NewProfilesManager(store)

	_, err := mgr.GetLatest(context.Background(), "uuid-1")
	if err == nil {
		t.Fatal("expected error when store fails")
	}
}

func TestGetLatest_ReturnsLatestVersion(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	for _, ver := range []string{"v1", "v2", "v3"} {
		if err := mgr.Set(context.Background(), testProfile("uuid-1", ver)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	got, err := mgr.GetLatest(context.Background(), "uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Version != "v3" {
		t.Fatalf("expected version %q, got %q", "v3", got.Version)
	}
}

// --- Delete tests ---

func TestDelete_Success(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	if err := mgr.Set(context.Background(), testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := mgr.Delete(context.Background(), "uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Profile should no longer be found.
	_, err = mgr.Get(context.Background(), "uuid-1", "v1")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestDelete_NotFound(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	err := mgr.Delete(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for deleting nonexistent profile")
	}

	var nf *ProfileNotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *ProfileNotFoundError, got %T", err)
	}
}

func TestDelete_StoreError(t *testing.T) {
	store := newMockProfileStore()
	store.delErr = errors.New("delete failure")
	mgr := NewProfilesManager(store)

	// Add a profile first so the mock doesn't return not-found.
	store.profiles["uuid-1"] = map[string]*Profile{
		"v1": testProfile("uuid-1", "v1"),
	}

	err := mgr.Delete(context.Background(), "uuid-1")
	if err == nil {
		t.Fatal("expected error when store fails")
	}
	if err.Error() != "delete failure" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelete_AllVersionsRemoved(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	if err := mgr.Set(context.Background(), testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mgr.Set(context.Background(), testProfile("uuid-1", "v2")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := mgr.Delete(context.Background(), "uuid-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := mgr.Get(context.Background(), "uuid-1", "v1")
	if err == nil {
		t.Fatal("expected v1 to be deleted")
	}
	_, err = mgr.Get(context.Background(), "uuid-1", "v2")
	if err == nil {
		t.Fatal("expected v2 to be deleted")
	}
	_, err = mgr.GetLatest(context.Background(), "uuid-1")
	if err == nil {
		t.Fatal("expected latest to be not found after delete")
	}
}

// --- Profile field tests ---

func TestSet_AllFieldsPreserved(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	profile := &Profile{
		UUID:           "uuid-full",
		Version:        "v1",
		Name:           []byte("name"),
		About:          []byte("about"),
		AboutEmoji:     []byte("emoji"),
		Avatar:         "avatar.png",
		Commitment:     []byte("commit"),
		PaymentAddress: []byte("payment"),
	}

	if err := mgr.Set(context.Background(), profile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := mgr.Get(context.Background(), "uuid-full", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got.Name) != "name" {
		t.Fatalf("Name mismatch: %q", string(got.Name))
	}
	if string(got.About) != "about" {
		t.Fatalf("About mismatch: %q", string(got.About))
	}
	if string(got.AboutEmoji) != "emoji" {
		t.Fatalf("AboutEmoji mismatch: %q", string(got.AboutEmoji))
	}
	if got.Avatar != "avatar.png" {
		t.Fatalf("Avatar mismatch: %q", got.Avatar)
	}
	if string(got.Commitment) != "commit" {
		t.Fatalf("Commitment mismatch: %q", string(got.Commitment))
	}
	if string(got.PaymentAddress) != "payment" {
		t.Fatalf("PaymentAddress mismatch: %q", string(got.PaymentAddress))
	}
}

func TestSet_NilByteFields(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	profile := &Profile{
		UUID:    "uuid-nil",
		Version: "v1",
	}

	if err := mgr.Set(context.Background(), profile); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := mgr.Get(context.Background(), "uuid-nil", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != nil {
		t.Fatal("expected nil Name")
	}
	if got.About != nil {
		t.Fatal("expected nil About")
	}
}

// --- Isolation tests ---

func TestSet_DifferentUUIDsIsolated(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	p1 := testProfile("uuid-1", "v1")
	p2 := testProfile("uuid-2", "v1")
	p2.Name = []byte("different-name")

	if err := mgr.Set(context.Background(), p1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mgr.Set(context.Background(), p2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got1, err := mgr.Get(context.Background(), "uuid-1", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got2, err := mgr.Get(context.Background(), "uuid-2", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(got1.Name) != "test-name" {
		t.Fatalf("expected uuid-1 Name %q, got %q", "test-name", string(got1.Name))
	}
	if string(got2.Name) != "different-name" {
		t.Fatalf("expected uuid-2 Name %q, got %q", "different-name", string(got2.Name))
	}
}

func TestDelete_DoesNotAffectOtherUUIDs(t *testing.T) {
	store := newMockProfileStore()
	mgr := NewProfilesManager(store)

	if err := mgr.Set(context.Background(), testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mgr.Set(context.Background(), testProfile("uuid-2", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := mgr.Delete(context.Background(), "uuid-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// uuid-2 should still exist.
	got, err := mgr.Get(context.Background(), "uuid-2", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-2" {
		t.Fatalf("expected UUID %q, got %q", "uuid-2", got.UUID)
	}
}
