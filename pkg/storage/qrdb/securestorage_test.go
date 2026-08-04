package qrdb

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/securestorage"
)

func TestSecureStorageStore_PutGet_Manifest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewSecureStorageStore(NewFakeKVStore())

	m := &securestorage.StorageManifest{Version: 1, Value: []byte("blob-v1")}
	if err := s.PutManifest(ctx, "u1", m); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	got, err := s.GetManifest(ctx, "u1")
	if err != nil || got.Version != 1 || string(got.Value) != "blob-v1" {
		t.Fatalf("GetManifest: err=%v got=%+v", err, got)
	}
}

func TestSecureStorageStore_GetManifest_Missing(t *testing.T) {
	t.Parallel()
	s := NewSecureStorageStore(NewFakeKVStore())
	_, err := s.GetManifest(context.Background(), "u1")
	var mnfe *securestorage.ManifestNotFoundError
	if !errors.As(err, &mnfe) {
		t.Fatalf("expected ManifestNotFoundError, got %T: %v", err, err)
	}
}

func TestSecureStorageStore_PutManifest_VersionMustIncrease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewSecureStorageStore(NewFakeKVStore())

	if err := s.PutManifest(ctx, "u1", &securestorage.StorageManifest{Version: 5, Value: []byte("a")}); err != nil {
		t.Fatal(err)
	}

	// Same version is a conflict.
	err := s.PutManifest(ctx, "u1", &securestorage.StorageManifest{Version: 5, Value: []byte("b")})
	var mvce *securestorage.ManifestVersionConflictError
	if !errors.As(err, &mvce) {
		t.Fatalf("expected ManifestVersionConflictError, got %T: %v", err, err)
	}

	// Older version also a conflict.
	err = s.PutManifest(ctx, "u1", &securestorage.StorageManifest{Version: 3, Value: []byte("c")})
	if !errors.As(err, &mvce) {
		t.Fatalf("expected ManifestVersionConflictError for older version, got %T: %v", err, err)
	}

	// Newer version succeeds.
	if err := s.PutManifest(ctx, "u1", &securestorage.StorageManifest{Version: 6, Value: []byte("d")}); err != nil {
		t.Fatalf("increment-by-one should succeed: %v", err)
	}
}

func TestSecureStorageStore_PutManifest_Nil(t *testing.T) {
	t.Parallel()
	s := NewSecureStorageStore(NewFakeKVStore())
	if err := s.PutManifest(context.Background(), "u1", nil); err == nil {
		t.Fatal("expected error for nil manifest")
	}
}

func TestSecureStorageStore_PutGet_Item(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewSecureStorageStore(NewFakeKVStore())

	key := []byte{0x01, 0x02, 0x03}
	item := &securestorage.StorageItem{Key: key, Value: []byte("secret")}
	if err := s.PutItem(ctx, "u1", item); err != nil {
		t.Fatalf("PutItem: %v", err)
	}

	got, err := s.GetItem(ctx, "u1", key)
	if err != nil {
		t.Fatalf("GetItem: %v", err)
	}
	if string(got.Value) != "secret" {
		t.Fatalf("wrong value: %+v", got)
	}
}

func TestSecureStorageStore_PutItem_Nil(t *testing.T) {
	t.Parallel()
	s := NewSecureStorageStore(NewFakeKVStore())
	if err := s.PutItem(context.Background(), "u1", nil); err == nil {
		t.Fatal("expected error for nil item")
	}
}

func TestSecureStorageStore_GetItem_Missing(t *testing.T) {
	t.Parallel()
	s := NewSecureStorageStore(NewFakeKVStore())
	_, err := s.GetItem(context.Background(), "u1", []byte("missing"))
	var sie *securestorage.StorageItemNotFoundError
	if !errors.As(err, &sie) {
		t.Fatalf("expected StorageItemNotFoundError, got %T: %v", err, err)
	}
}

func TestSecureStorageStore_DeleteItem(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewSecureStorageStore(NewFakeKVStore())

	key := []byte("k")
	if err := s.PutItem(ctx, "u1", &securestorage.StorageItem{Key: key, Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteItem(ctx, "u1", key); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}
	_, err := s.GetItem(ctx, "u1", key)
	var sie *securestorage.StorageItemNotFoundError
	if !errors.As(err, &sie) {
		t.Fatal("expected item absent after Delete")
	}
}

func TestSecureStorageStore_DeleteItem_Missing(t *testing.T) {
	t.Parallel()
	s := NewSecureStorageStore(NewFakeKVStore())
	err := s.DeleteItem(context.Background(), "u1", []byte("k"))
	var sie *securestorage.StorageItemNotFoundError
	if !errors.As(err, &sie) {
		t.Fatalf("expected StorageItemNotFoundError, got %T: %v", err, err)
	}
}

func TestSecureStorageStore_DeleteAll_RemovesEverything(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewSecureStorageStore(NewFakeKVStore())

	if err := s.PutManifest(ctx, "u1", &securestorage.StorageManifest{Version: 1, Value: []byte("m")}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutItem(ctx, "u1", &securestorage.StorageItem{Key: []byte("k1"), Value: []byte("v1")}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutItem(ctx, "u1", &securestorage.StorageItem{Key: []byte("k2"), Value: []byte("v2")}); err != nil {
		t.Fatal(err)
	}

	// Unrelated account must not be affected.
	if err := s.PutManifest(ctx, "u2", &securestorage.StorageManifest{Version: 1, Value: []byte("x")}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteAll(ctx, "u1"); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}

	if _, err := s.GetManifest(ctx, "u1"); err == nil {
		t.Fatal("manifest should be gone")
	}
	if _, err := s.GetItem(ctx, "u1", []byte("k1")); err == nil {
		t.Fatal("k1 should be gone")
	}
	if _, err := s.GetManifest(ctx, "u2"); err != nil {
		t.Fatalf("u2 manifest should remain: %v", err)
	}
}
