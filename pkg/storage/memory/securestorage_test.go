package memory

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/securestorage"
)

// --------------------------------------------------------------------------
// NewMemoryManifestStore
// --------------------------------------------------------------------------

func TestNewMemoryManifestStore_NotNil(t *testing.T) {
	s := NewMemoryManifestStore()
	if s == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestNewMemoryManifestStore_EmptyMaps(t *testing.T) {
	s := NewMemoryManifestStore()
	if len(s.manifests) != 0 {
		t.Errorf("expected empty manifests map, got %d", len(s.manifests))
	}
	if len(s.items) != 0 {
		t.Errorf("expected empty items map, got %d", len(s.items))
	}
}

// --------------------------------------------------------------------------
// GetManifest
// --------------------------------------------------------------------------

func TestMemoryManifestStore_GetManifest_NotFound(t *testing.T) {
	s := NewMemoryManifestStore()
	_, err := s.GetManifest(context.Background(), "acct-1")
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
	if _, ok := err.(*securestorage.ManifestNotFoundError); !ok {
		t.Errorf("expected *ManifestNotFoundError, got %T", err)
	}
}

func TestMemoryManifestStore_GetManifest_AfterPut(t *testing.T) {
	s := NewMemoryManifestStore()
	m := &securestorage.StorageManifest{Version: 1, Value: []byte("blob")}
	if err := s.PutManifest(context.Background(), "acct-1", m); err != nil {
		t.Fatalf("PutManifest failed: %v", err)
	}
	got, err := s.GetManifest(context.Background(), "acct-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("got version %d, want 1", got.Version)
	}
	if !bytes.Equal(got.Value, []byte("blob")) {
		t.Errorf("got value %q, want %q", got.Value, "blob")
	}
}

func TestMemoryManifestStore_GetManifest_ReturnsDeepCopy(t *testing.T) {
	s := NewMemoryManifestStore()
	m := &securestorage.StorageManifest{Version: 1, Value: []byte("original")}
	if err := s.PutManifest(context.Background(), "acct-iso", m); err != nil {
		t.Fatalf("PutManifest failed: %v", err)
	}
	got, _ := s.GetManifest(context.Background(), "acct-iso")
	got.Value[0] = 'X'

	got2, _ := s.GetManifest(context.Background(), "acct-iso")
	if got2.Value[0] == 'X' {
		t.Error("GetManifest did not return an independent copy")
	}
}

// --------------------------------------------------------------------------
// PutManifest
// --------------------------------------------------------------------------

func TestMemoryManifestStore_PutManifest_FirstWrite(t *testing.T) {
	s := NewMemoryManifestStore()
	m := &securestorage.StorageManifest{Version: 1, Value: []byte("v1")}
	if err := s.PutManifest(context.Background(), "acct-1", m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMemoryManifestStore_PutManifest_VersionConflict_SameVersion(t *testing.T) {
	s := NewMemoryManifestStore()
	m1 := &securestorage.StorageManifest{Version: 1, Value: []byte("v1")}
	if err := s.PutManifest(context.Background(), "acct-vc", m1); err != nil {
		t.Fatalf("first put failed: %v", err)
	}
	// Submit same version (not greater).
	m2 := &securestorage.StorageManifest{Version: 1, Value: []byte("v1-dup")}
	err := s.PutManifest(context.Background(), "acct-vc", m2)
	if err == nil {
		t.Fatal("expected version conflict error")
	}
	if _, ok := err.(*securestorage.ManifestVersionConflictError); !ok {
		t.Errorf("expected *ManifestVersionConflictError, got %T", err)
	}
}

func TestMemoryManifestStore_PutManifest_VersionConflict_OlderVersion(t *testing.T) {
	s := NewMemoryManifestStore()
	m := &securestorage.StorageManifest{Version: 5, Value: []byte("v5")}
	if err := s.PutManifest(context.Background(), "acct-old", m); err != nil {
		t.Fatalf("first put failed: %v", err)
	}
	m2 := &securestorage.StorageManifest{Version: 3, Value: []byte("older")}
	err := s.PutManifest(context.Background(), "acct-old", m2)
	if err == nil {
		t.Fatal("expected version conflict error for older version")
	}
}

func TestMemoryManifestStore_PutManifest_UpdateSucceeds(t *testing.T) {
	s := NewMemoryManifestStore()
	m1 := &securestorage.StorageManifest{Version: 1, Value: []byte("v1")}
	if err := s.PutManifest(context.Background(), "acct-upd", m1); err != nil {
		t.Fatalf("first put failed: %v", err)
	}
	m2 := &securestorage.StorageManifest{Version: 2, Value: []byte("v2")}
	if err := s.PutManifest(context.Background(), "acct-upd", m2); err != nil {
		t.Fatalf("second put failed: %v", err)
	}
	got, _ := s.GetManifest(context.Background(), "acct-upd")
	if got.Version != 2 {
		t.Errorf("got version %d, want 2", got.Version)
	}
}

func TestMemoryManifestStore_PutManifest_IsolatesCallerReference(t *testing.T) {
	s := NewMemoryManifestStore()
	m := &securestorage.StorageManifest{Version: 1, Value: []byte("original")}
	if err := s.PutManifest(context.Background(), "acct-iso2", m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m.Value[0] = 'X'
	got, _ := s.GetManifest(context.Background(), "acct-iso2")
	if got.Value[0] == 'X' {
		t.Error("PutManifest did not isolate caller's reference")
	}
}

// --------------------------------------------------------------------------
// GetItem / PutItem
// --------------------------------------------------------------------------

func TestMemoryManifestStore_GetItem_NotFound(t *testing.T) {
	s := NewMemoryManifestStore()
	_, err := s.GetItem(context.Background(), "acct-1", []byte{0x01})
	if err == nil {
		t.Fatal("expected error for missing item")
	}
	if _, ok := err.(*securestorage.StorageItemNotFoundError); !ok {
		t.Errorf("expected *StorageItemNotFoundError, got %T", err)
	}
}

func TestMemoryManifestStore_PutItem_ThenGet(t *testing.T) {
	s := NewMemoryManifestStore()
	item := &securestorage.StorageItem{Key: []byte{0xAA, 0xBB}, Value: []byte("val")}
	if err := s.PutItem(context.Background(), "acct-1", item); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := s.GetItem(context.Background(), "acct-1", []byte{0xAA, 0xBB})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got.Value, []byte("val")) {
		t.Errorf("got %q, want %q", got.Value, "val")
	}
}

func TestMemoryManifestStore_PutItem_OverwritesSameKey(t *testing.T) {
	s := NewMemoryManifestStore()
	key := []byte{0x01}
	if err := s.PutItem(context.Background(), "acct-1", &securestorage.StorageItem{Key: key, Value: []byte("v1")}); err != nil {
		t.Fatalf("first put failed: %v", err)
	}
	if err := s.PutItem(context.Background(), "acct-1", &securestorage.StorageItem{Key: key, Value: []byte("v2")}); err != nil {
		t.Fatalf("second put failed: %v", err)
	}
	got, _ := s.GetItem(context.Background(), "acct-1", key)
	if !bytes.Equal(got.Value, []byte("v2")) {
		t.Errorf("got %q, want %q", got.Value, "v2")
	}
}

func TestMemoryManifestStore_GetItem_ReturnsDeepCopy(t *testing.T) {
	s := NewMemoryManifestStore()
	key := []byte{0x02}
	if err := s.PutItem(context.Background(), "acct-1", &securestorage.StorageItem{Key: key, Value: []byte("original")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, _ := s.GetItem(context.Background(), "acct-1", key)
	got.Value[0] = 'X'
	got2, _ := s.GetItem(context.Background(), "acct-1", key)
	if got2.Value[0] == 'X' {
		t.Error("GetItem did not return an independent copy")
	}
}

func TestMemoryManifestStore_ItemsArePerAccount(t *testing.T) {
	s := NewMemoryManifestStore()
	key := []byte{0x10}
	if err := s.PutItem(context.Background(), "acct-A", &securestorage.StorageItem{Key: key, Value: []byte("A-val")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err := s.GetItem(context.Background(), "acct-B", key)
	if err == nil {
		t.Fatal("expected error: items should be isolated per account")
	}
}

// --------------------------------------------------------------------------
// DeleteItem
// --------------------------------------------------------------------------

func TestMemoryManifestStore_DeleteItem_Success(t *testing.T) {
	s := NewMemoryManifestStore()
	key := []byte{0x03}
	if err := s.PutItem(context.Background(), "acct-1", &securestorage.StorageItem{Key: key, Value: []byte("v")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.DeleteItem(context.Background(), "acct-1", key); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err := s.GetItem(context.Background(), "acct-1", key)
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestMemoryManifestStore_DeleteItem_NotFound(t *testing.T) {
	s := NewMemoryManifestStore()
	err := s.DeleteItem(context.Background(), "acct-1", []byte{0xFF})
	if err == nil {
		t.Fatal("expected error for non-existent item")
	}
	if _, ok := err.(*securestorage.StorageItemNotFoundError); !ok {
		t.Errorf("expected *StorageItemNotFoundError, got %T", err)
	}
}

// --------------------------------------------------------------------------
// DeleteAll
// --------------------------------------------------------------------------

func TestMemoryManifestStore_DeleteAll_RemovesManifest(t *testing.T) {
	s := NewMemoryManifestStore()
	m := &securestorage.StorageManifest{Version: 1, Value: []byte("v1")}
	if err := s.PutManifest(context.Background(), "acct-del", m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.DeleteAll(context.Background(), "acct-del"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err := s.GetManifest(context.Background(), "acct-del")
	if err == nil {
		t.Fatal("expected error after DeleteAll")
	}
}

func TestMemoryManifestStore_DeleteAll_RemovesItems(t *testing.T) {
	s := NewMemoryManifestStore()
	key := []byte{0x04}
	if err := s.PutItem(context.Background(), "acct-del2", &securestorage.StorageItem{Key: key, Value: []byte("v")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.DeleteAll(context.Background(), "acct-del2"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err := s.GetItem(context.Background(), "acct-del2", key)
	if err == nil {
		t.Fatal("expected error for item after DeleteAll")
	}
}

func TestMemoryManifestStore_DeleteAll_DoesNotAffectOtherAccounts(t *testing.T) {
	s := NewMemoryManifestStore()
	m := &securestorage.StorageManifest{Version: 1, Value: []byte("v1")}
	if err := s.PutManifest(context.Background(), "acct-keep", m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := s.DeleteAll(context.Background(), "acct-delete-other"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := s.GetManifest(context.Background(), "acct-keep")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("got version %d, want 1", got.Version)
	}
}

func TestMemoryManifestStore_DeleteAll_EmptyAccount_NoError(t *testing.T) {
	s := NewMemoryManifestStore()
	if err := s.DeleteAll(context.Background(), "no-data-acct"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --------------------------------------------------------------------------
// hexKey helper
// --------------------------------------------------------------------------

func TestHexKey_EmptyInput(t *testing.T) {
	if hexKey(nil) != "" {
		t.Error("expected empty string for nil input")
	}
	if hexKey([]byte{}) != "" {
		t.Error("expected empty string for empty byte slice")
	}
}

func TestHexKey_CorrectEncoding(t *testing.T) {
	got := hexKey([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if got != "deadbeef" {
		t.Errorf("got %q, want %q", got, "deadbeef")
	}
}

func TestHexKey_UniquePerInput(t *testing.T) {
	a := hexKey([]byte{0x01})
	b := hexKey([]byte{0x02})
	if a == b {
		t.Error("expected different hex keys for different inputs")
	}
}

// --------------------------------------------------------------------------
// bytesEqual helper
// --------------------------------------------------------------------------

func TestBytesEqual_EqualSlices(t *testing.T) {
	if !bytesEqual([]byte("hello"), []byte("hello")) {
		t.Error("expected equal")
	}
}

func TestBytesEqual_UnequalSlices(t *testing.T) {
	if bytesEqual([]byte("hello"), []byte("world")) {
		t.Error("expected unequal")
	}
}

// --------------------------------------------------------------------------
// Concurrency
// --------------------------------------------------------------------------

func TestMemoryManifestStore_ConcurrentPutGet(t *testing.T) {
	s := NewMemoryManifestStore()
	const n = 50

	// Pre-populate a manifest.
	m := &securestorage.StorageManifest{Version: 1, Value: []byte("v1")}
	if err := s.PutManifest(context.Background(), "conc-acct", m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = s.GetManifest(context.Background(), "conc-acct")
		}()
	}
	wg.Wait()
}

func TestMemoryManifestStore_ConcurrentPutItems(t *testing.T) {
	s := NewMemoryManifestStore()
	const n = 50

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			key := []byte{byte(idx)}
			_ = s.PutItem(context.Background(), "conc-item-acct", &securestorage.StorageItem{
				Key:   key,
				Value: []byte("val"),
			})
		}(i)
	}
	wg.Wait()
}
