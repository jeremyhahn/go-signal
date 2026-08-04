package memory

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/profiles"
)

func testProfile(uuid, version string) *profiles.Profile {
	return &profiles.Profile{
		UUID:           uuid,
		Version:        version,
		Name:           []byte("name-" + uuid),
		About:          []byte("about-" + uuid),
		AboutEmoji:     []byte("emoji-" + uuid),
		Avatar:         "avatar-" + uuid,
		Commitment:     []byte("commitment-" + uuid),
		PaymentAddress: []byte("payment-" + uuid),
	}
}

// --- NewMemoryProfileStore tests ---

func TestNewMemoryProfileStore(t *testing.T) {
	store := NewMemoryProfileStore()
	if store == nil {
		t.Fatal("expected non-nil store")
		return
	}
	if store.byUUID == nil {
		t.Fatal("expected byUUID map to be initialized")
	}
	if store.latestVersion == nil {
		t.Fatal("expected latestVersion map to be initialized")
	}
}

func TestNewMemoryProfileStoreEmptyMaps(t *testing.T) {
	store := NewMemoryProfileStore()
	if len(store.byUUID) != 0 {
		t.Fatalf("expected empty byUUID map, got %d entries", len(store.byUUID))
	}
	if len(store.latestVersion) != 0 {
		t.Fatalf("expected empty latestVersion map, got %d entries", len(store.latestVersion))
	}
}

// --- Set tests ---

func TestProfileStore_Set(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	p := testProfile("uuid-1", "v1")
	err := store.Set(ctx, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.Get(ctx, "uuid-1", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-1" {
		t.Fatalf("expected UUID %q, got %q", "uuid-1", got.UUID)
	}
}

func TestProfileStore_SetMultipleVersions(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	if err := store.Set(ctx, testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.Set(ctx, testProfile("uuid-1", "v2")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got1, err := store.Get(ctx, "uuid-1", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got1.Version != "v1" {
		t.Fatalf("expected version %q, got %q", "v1", got1.Version)
	}

	got2, err := store.Get(ctx, "uuid-1", "v2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2.Version != "v2" {
		t.Fatalf("expected version %q, got %q", "v2", got2.Version)
	}
}

func TestProfileStore_SetOverwriteVersion(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	if err := store.Set(ctx, testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated := &profiles.Profile{
		UUID:    "uuid-1",
		Version: "v1",
		Name:    []byte("updated-name"),
	}
	if err := store.Set(ctx, updated); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.Get(ctx, "uuid-1", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got.Name) != "updated-name" {
		t.Fatalf("expected Name %q, got %q", "updated-name", string(got.Name))
	}
}

func TestProfileStore_SetDeepCopy(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	p := testProfile("uuid-dc", "v1")
	if err := store.Set(ctx, p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate original.
	p.Name[0] = 0xFF

	got, err := store.Get(ctx, "uuid-dc", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name[0] == 0xFF {
		t.Fatal("mutation of original affected stored data")
	}
}

func TestProfileStore_SetNilByteFields(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	p := &profiles.Profile{
		UUID:    "uuid-nil",
		Version: "v1",
		Avatar:  "avatar.png",
	}
	if err := store.Set(ctx, p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.Get(ctx, "uuid-nil", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != nil {
		t.Fatal("expected nil Name")
	}
	if got.About != nil {
		t.Fatal("expected nil About")
	}
	if got.Commitment != nil {
		t.Fatal("expected nil Commitment")
	}
}

// --- Get tests ---

func TestProfileStore_GetNotFound(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent", "v1")
	if err == nil {
		t.Fatal("expected error for nonexistent profile")
	}

	if _, ok := err.(*profiles.ProfileNotFoundError); !ok {
		t.Fatalf("expected *profiles.ProfileNotFoundError, got %T", err)
	}
}

func TestProfileStore_GetVersionNotFound(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	if err := store.Set(ctx, testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := store.Get(ctx, "uuid-1", "v999")
	if err == nil {
		t.Fatal("expected error for nonexistent version")
	}

	if _, ok := err.(*profiles.ProfileNotFoundError); !ok {
		t.Fatalf("expected *profiles.ProfileNotFoundError, got %T", err)
	}
}

func TestProfileStore_GetDeepCopy(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	if err := store.Set(ctx, testProfile("uuid-gdc", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.Get(ctx, "uuid-gdc", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate returned value.
	got.Name[0] = 0xAA

	got2, err := store.Get(ctx, "uuid-gdc", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2.Name[0] == 0xAA {
		t.Fatal("mutation of returned value affected stored data")
	}
}

func TestProfileStore_GetAllFieldsPreserved(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	p := testProfile("uuid-fields", "v1")
	if err := store.Set(ctx, p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.Get(ctx, "uuid-fields", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(got.Name, p.Name) {
		t.Fatal("Name mismatch")
	}
	if !bytes.Equal(got.About, p.About) {
		t.Fatal("About mismatch")
	}
	if !bytes.Equal(got.AboutEmoji, p.AboutEmoji) {
		t.Fatal("AboutEmoji mismatch")
	}
	if got.Avatar != p.Avatar {
		t.Fatalf("Avatar mismatch: %q vs %q", got.Avatar, p.Avatar)
	}
	if !bytes.Equal(got.Commitment, p.Commitment) {
		t.Fatal("Commitment mismatch")
	}
	if !bytes.Equal(got.PaymentAddress, p.PaymentAddress) {
		t.Fatal("PaymentAddress mismatch")
	}
}

// --- GetLatest tests ---

func TestProfileStore_GetLatest(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	if err := store.Set(ctx, testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p2 := testProfile("uuid-1", "v2")
	p2.Name = []byte("latest-name")
	if err := store.Set(ctx, p2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetLatest(ctx, "uuid-1")
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

func TestProfileStore_GetLatestNotFound(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	_, err := store.GetLatest(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent profile")
	}

	if _, ok := err.(*profiles.ProfileNotFoundError); !ok {
		t.Fatalf("expected *profiles.ProfileNotFoundError, got %T", err)
	}
}

func TestProfileStore_GetLatestDeepCopy(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	if err := store.Set(ctx, testProfile("uuid-ldc", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetLatest(ctx, "uuid-ldc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got.Name[0] = 0xBB

	got2, err := store.GetLatest(ctx, "uuid-ldc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2.Name[0] == 0xBB {
		t.Fatal("mutation of returned value affected stored data")
	}
}

func TestProfileStore_GetLatestUpdatesOnNewVersion(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	for _, ver := range []string{"v1", "v2", "v3"} {
		if err := store.Set(ctx, testProfile("uuid-1", ver)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	got, err := store.GetLatest(ctx, "uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Version != "v3" {
		t.Fatalf("expected version %q, got %q", "v3", got.Version)
	}
}

// --- Delete tests ---

func TestProfileStore_Delete(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	if err := store.Set(ctx, testProfile("uuid-del", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.Delete(ctx, "uuid-del"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := store.Get(ctx, "uuid-del", "v1")
	if err == nil {
		t.Fatal("expected error after delete")
	}

	_, err = store.GetLatest(ctx, "uuid-del")
	if err == nil {
		t.Fatal("expected error for latest after delete")
	}
}

func TestProfileStore_DeleteNotFound_Idempotent(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	// Deleting a non-existent profile is idempotent and returns nil.
	err := store.Delete(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("expected nil for nonexistent profile delete, got %v", err)
	}
}

func TestProfileStore_DeleteAllVersions(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	if err := store.Set(ctx, testProfile("uuid-del", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.Set(ctx, testProfile("uuid-del", "v2")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.Delete(ctx, "uuid-del"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := store.Get(ctx, "uuid-del", "v1")
	if err == nil {
		t.Fatal("expected v1 to be deleted")
	}
	_, err = store.Get(ctx, "uuid-del", "v2")
	if err == nil {
		t.Fatal("expected v2 to be deleted")
	}
}

func TestProfileStore_DeleteDoesNotAffectOthers(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	if err := store.Set(ctx, testProfile("uuid-1", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := store.Set(ctx, testProfile("uuid-2", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.Delete(ctx, "uuid-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.Get(ctx, "uuid-2", "v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-2" {
		t.Fatalf("expected UUID %q, got %q", "uuid-2", got.UUID)
	}
}

// --- cloneProfile tests ---

func TestCloneProfile(t *testing.T) {
	original := testProfile("uuid-clone", "v1")
	clone := cloneProfile(original)

	if clone.UUID != original.UUID {
		t.Fatalf("UUID mismatch: %q vs %q", clone.UUID, original.UUID)
	}
	if clone.Avatar != original.Avatar {
		t.Fatalf("Avatar mismatch: %q vs %q", clone.Avatar, original.Avatar)
	}

	// Mutate clone, ensure original is unaffected.
	clone.Name[0] = 0xFF
	if original.Name[0] == 0xFF {
		t.Fatal("clone mutation affected original Name")
	}

	clone.About[0] = 0xAA
	if original.About[0] == 0xAA {
		t.Fatal("clone mutation affected original About")
	}

	clone.Commitment[0] = 0xBB
	if original.Commitment[0] == 0xBB {
		t.Fatal("clone mutation affected original Commitment")
	}

	clone.PaymentAddress[0] = 0xCC
	if original.PaymentAddress[0] == 0xCC {
		t.Fatal("clone mutation affected original PaymentAddress")
	}
}

func TestCloneProfileNilBytes(t *testing.T) {
	original := &profiles.Profile{
		UUID:    "uuid-nil",
		Version: "v1",
	}
	clone := cloneProfile(original)

	if clone.Name != nil {
		t.Fatal("expected nil Name on clone")
	}
	if clone.About != nil {
		t.Fatal("expected nil About on clone")
	}
	if clone.AboutEmoji != nil {
		t.Fatal("expected nil AboutEmoji on clone")
	}
	if clone.Commitment != nil {
		t.Fatal("expected nil Commitment on clone")
	}
	if clone.PaymentAddress != nil {
		t.Fatal("expected nil PaymentAddress on clone")
	}
}

// --- Concurrency tests ---

func TestProfileStoreConcurrentSetAndGet(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			ver := "v" + string(rune('0'+idx%10))
			_ = store.Set(ctx, testProfile("uuid-conc", ver))
		}(i)
		go func() {
			defer wg.Done()
			_, _ = store.GetLatest(ctx, "uuid-conc")
		}()
	}
	wg.Wait()
}

func TestProfileStoreConcurrentSetAndDelete(t *testing.T) {
	store := NewMemoryProfileStore()
	ctx := context.Background()

	// Pre-populate.
	if err := store.Set(ctx, testProfile("uuid-cd", "v1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			ver := "v" + string(rune('0'+idx%10))
			_ = store.Set(ctx, testProfile("uuid-cd", ver))
		}(i)
		go func() {
			defer wg.Done()
			_ = store.Delete(ctx, "uuid-cd")
		}()
	}
	wg.Wait()
}

// --- Interface satisfaction ---

func TestMemoryProfileStoreImplementsInterface(t *testing.T) {
	var _ profiles.ProfileStore = (*MemoryProfileStore)(nil)
}

func TestMemoryProfileStoreInterfaceNonNil(t *testing.T) {
	var store profiles.ProfileStore = NewMemoryProfileStore()
	_ = store
}
