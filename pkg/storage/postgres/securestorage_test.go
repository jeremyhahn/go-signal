package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/securestorage"
)

func TestManifestStore_PutManifest_GetManifest_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	ctx := context.Background()

	accountUUID := uuid.NewString()
	m := &securestorage.StorageManifest{Version: 1, Value: []byte("encrypted-manifest-v1")}

	if err := s.PutManifest(ctx, accountUUID, m); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	got, err := s.GetManifest(ctx, accountUUID)
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if got.Version != 1 || string(got.Value) != "encrypted-manifest-v1" {
		t.Fatalf("GetManifest returned unexpected manifest: %+v", got)
	}
}

func TestManifestStore_GetManifest_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)

	_, err := s.GetManifest(context.Background(), uuid.NewString())
	var nfe *securestorage.ManifestNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected ManifestNotFoundError, got %T: %v", err, err)
	}
}

func TestManifestStore_PutManifest_EnforcesVersionIncrement(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	ctx := context.Background()

	accountUUID := uuid.NewString()
	if err := s.PutManifest(ctx, accountUUID, &securestorage.StorageManifest{Version: 5, Value: []byte("a")}); err != nil {
		t.Fatalf("PutManifest v5: %v", err)
	}

	// Equal version must be rejected.
	err := s.PutManifest(ctx, accountUUID, &securestorage.StorageManifest{Version: 5, Value: []byte("b")})
	var vce *securestorage.ManifestVersionConflictError
	if !errors.As(err, &vce) {
		t.Fatalf("expected ManifestVersionConflictError for equal version, got %T: %v", err, err)
	}

	// Older version must also be rejected.
	err = s.PutManifest(ctx, accountUUID, &securestorage.StorageManifest{Version: 3, Value: []byte("c")})
	if !errors.As(err, &vce) {
		t.Fatalf("expected ManifestVersionConflictError for older version, got %T: %v", err, err)
	}

	// Strictly greater version must succeed.
	if err := s.PutManifest(ctx, accountUUID, &securestorage.StorageManifest{Version: 6, Value: []byte("d")}); err != nil {
		t.Fatalf("PutManifest v6 (increment): %v", err)
	}
	got, err := s.GetManifest(ctx, accountUUID)
	if err != nil {
		t.Fatalf("GetManifest after v6 update: %v", err)
	}
	if got.Version != 6 || string(got.Value) != "d" {
		t.Fatalf("manifest not updated to v6: %+v", got)
	}
}

func TestManifestStore_PutManifest_Nil_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)

	if err := s.PutManifest(context.Background(), uuid.NewString(), nil); err == nil {
		t.Fatal("expected error for nil manifest")
	}
}

func TestManifestStore_PutItem_GetItem_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	ctx := context.Background()

	accountUUID := uuid.NewString()
	key := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	item := &securestorage.StorageItem{Key: key, Value: []byte("encrypted-item-value")}

	if err := s.PutItem(ctx, accountUUID, item); err != nil {
		t.Fatalf("PutItem: %v", err)
	}
	got, err := s.GetItem(ctx, accountUUID, key)
	if err != nil {
		t.Fatalf("GetItem: %v", err)
	}
	if string(got.Value) != "encrypted-item-value" {
		t.Fatalf("GetItem returned unexpected value: %q", got.Value)
	}
}

func TestManifestStore_PutItem_Overwrites_ExistingValue(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	ctx := context.Background()

	accountUUID := uuid.NewString()
	key := []byte("item-key")

	if err := s.PutItem(ctx, accountUUID, &securestorage.StorageItem{Key: key, Value: []byte("v1")}); err != nil {
		t.Fatalf("PutItem #1: %v", err)
	}
	if err := s.PutItem(ctx, accountUUID, &securestorage.StorageItem{Key: key, Value: []byte("v2")}); err != nil {
		t.Fatalf("PutItem #2 (overwrite): %v", err)
	}
	got, err := s.GetItem(ctx, accountUUID, key)
	if err != nil {
		t.Fatalf("GetItem after overwrite: %v", err)
	}
	if string(got.Value) != "v2" {
		t.Fatalf("PutItem did not overwrite: %q", got.Value)
	}
}

func TestManifestStore_GetItem_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)

	_, err := s.GetItem(context.Background(), uuid.NewString(), []byte("no-such-key"))
	var nfe *securestorage.StorageItemNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected StorageItemNotFoundError, got %T: %v", err, err)
	}
}

func TestManifestStore_DeleteItem_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	ctx := context.Background()

	accountUUID := uuid.NewString()
	key := []byte("del-key")

	if err := s.PutItem(ctx, accountUUID, &securestorage.StorageItem{Key: key, Value: []byte("v")}); err != nil {
		t.Fatalf("PutItem: %v", err)
	}
	if err := s.DeleteItem(ctx, accountUUID, key); err != nil {
		t.Fatalf("DeleteItem: %v", err)
	}
	_, err := s.GetItem(ctx, accountUUID, key)
	var nfe *securestorage.StorageItemNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected StorageItemNotFoundError after delete, got %T: %v", err, err)
	}
}

func TestManifestStore_DeleteItem_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)

	err := s.DeleteItem(context.Background(), uuid.NewString(), []byte("absent"))
	var nfe *securestorage.StorageItemNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected StorageItemNotFoundError, got %T: %v", err, err)
	}
}

func TestManifestStore_DeleteAll_WipesBothTablesForAccount(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	ctx := context.Background()

	// Account under test.
	a1 := uuid.NewString()
	if err := s.PutManifest(ctx, a1, &securestorage.StorageManifest{Version: 1, Value: []byte("m1")}); err != nil {
		t.Fatalf("PutManifest a1: %v", err)
	}
	if err := s.PutItem(ctx, a1, &securestorage.StorageItem{Key: []byte("k1"), Value: []byte("v1")}); err != nil {
		t.Fatalf("PutItem k1: %v", err)
	}
	if err := s.PutItem(ctx, a1, &securestorage.StorageItem{Key: []byte("k2"), Value: []byte("v2")}); err != nil {
		t.Fatalf("PutItem k2: %v", err)
	}

	// Unrelated account that must survive DeleteAll.
	a2 := uuid.NewString()
	if err := s.PutManifest(ctx, a2, &securestorage.StorageManifest{Version: 1, Value: []byte("m2")}); err != nil {
		t.Fatalf("PutManifest a2: %v", err)
	}

	if err := s.DeleteAll(ctx, a1); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}

	if _, err := s.GetManifest(ctx, a1); err == nil {
		t.Fatal("a1 manifest should be gone after DeleteAll")
	}
	if _, err := s.GetItem(ctx, a1, []byte("k1")); err == nil {
		t.Fatal("a1 item k1 should be gone after DeleteAll")
	}
	if _, err := s.GetItem(ctx, a1, []byte("k2")); err == nil {
		t.Fatal("a1 item k2 should be gone after DeleteAll")
	}

	// Unrelated account must be untouched.
	if _, err := s.GetManifest(ctx, a2); err != nil {
		t.Fatalf("a2 manifest should remain after a1 DeleteAll: %v", err)
	}
}

func TestManifestStore_DeleteItem_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	c.Close()

	err := s.DeleteItem(context.Background(), uuid.NewString(), []byte("some-key"))
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *securestorage.StorageItemNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not StorageItemNotFoundError")
	}
}

func TestManifestStore_PutItem_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	c.Close()

	err := s.PutItem(context.Background(), uuid.NewString(), &securestorage.StorageItem{
		Key:   []byte("k"),
		Value: []byte("v"),
	})
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestManifestStore_PutItem_NilItem_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)

	err := s.PutItem(context.Background(), uuid.NewString(), nil)
	if err == nil {
		t.Fatal("expected error for nil item, got nil")
	}
}

func TestManifestStore_GetItem_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	c.Close()

	_, err := s.GetItem(context.Background(), uuid.NewString(), []byte("key"))
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *securestorage.StorageItemNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not StorageItemNotFoundError")
	}
}

func TestManifestStore_PutManifest_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	c.Close()

	err := s.PutManifest(context.Background(), uuid.NewString(),
		&securestorage.StorageManifest{Version: 1, Value: []byte("v")})
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestManifestStore_DeleteAll_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	c.Close()

	err := s.DeleteAll(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestManifestStore_DeleteAll_EmptyAccount_IsIdempotent(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)

	// DeleteAll on an account with no data must not error.
	if err := s.DeleteAll(context.Background(), uuid.NewString()); err != nil {
		t.Fatalf("DeleteAll on empty account: %v", err)
	}
}

// TestManifestStore_GetManifest_PoolClosed_ReturnsError exercises the
// pool-error branch in getManifest (securestorage.go:51). The pool is closed
// before GetManifest is called so QueryRow returns a non-ErrNoRows error,
// which is wrapped and returned.
func TestManifestStore_GetManifest_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewManifestStore(c)
	c.Close()

	_, err := s.GetManifest(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool, got nil")
	}
	var nfe *securestorage.ManifestNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not ManifestNotFoundError")
	}
}
