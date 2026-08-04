package securestorage_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

func newStorageManager() *securestorage.SecureStorageManager {
	m := securestorage.NewSecureStorageManager(slog.Default())
	m.SetManifestStore(memory.NewMemoryManifestStore())
	return m
}

func item(key, value string) *securestorage.StorageItem {
	return &securestorage.StorageItem{Key: []byte(key), Value: []byte(value)}
}

func TestSecureStorage_WriteThenGetManifestAndRead(t *testing.T) {
	m := newStorageManager()
	ctx := context.Background()
	const acct = "acct-1"

	// No manifest initially.
	if got, err := m.GetManifest(ctx, acct); err != nil || got != nil {
		t.Fatalf("expected (nil,nil), got (%v,%v)", got, err)
	}

	manifest := &securestorage.StorageManifest{Version: 1, Value: []byte("manifest-v1")}
	inserts := []*securestorage.StorageItem{item("k1", "v1"), item("k2", "v2")}
	conflict, err := m.Write(ctx, acct, manifest, inserts, nil, false)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if conflict != nil {
		t.Fatalf("unexpected conflict: %+v", conflict)
	}

	got, err := m.GetManifest(ctx, acct)
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if got == nil || got.Version != 1 || !bytes.Equal(got.Value, []byte("manifest-v1")) {
		t.Fatalf("unexpected manifest: %+v", got)
	}

	items, err := m.Read(ctx, acct, [][]byte{[]byte("k1"), []byte("k2"), []byte("missing")})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 items (missing omitted), got %d", len(items))
	}
}

func TestSecureStorage_VersionConflictReturnsCurrentAndDoesNotMutate(t *testing.T) {
	m := newStorageManager()
	ctx := context.Background()
	const acct = "acct-2"

	if _, err := m.Write(ctx, acct, &securestorage.StorageManifest{Version: 5, Value: []byte("v5")},
		[]*securestorage.StorageItem{item("a", "1")}, nil, false); err != nil {
		t.Fatalf("initial write: %v", err)
	}

	// Re-writing with an equal-or-lower version is rejected with the current
	// manifest, and must not apply the (would-be) item change.
	conflict, err := m.Write(ctx, acct, &securestorage.StorageManifest{Version: 5, Value: []byte("v5-again")},
		[]*securestorage.StorageItem{item("a", "CHANGED")}, nil, false)
	if err != nil {
		t.Fatalf("conflicting write: %v", err)
	}
	if conflict == nil || conflict.Version != 5 || !bytes.Equal(conflict.Value, []byte("v5")) {
		t.Fatalf("expected current manifest v5 as conflict, got %+v", conflict)
	}
	items, _ := m.Read(ctx, acct, [][]byte{[]byte("a")})
	if len(items) != 1 || !bytes.Equal(items[0].Value, []byte("1")) {
		t.Fatalf("item must be unchanged after a rejected write, got %+v", items)
	}
}

func TestSecureStorage_DeleteKeysAndBumpVersion(t *testing.T) {
	m := newStorageManager()
	ctx := context.Background()
	const acct = "acct-3"

	_, err := m.Write(ctx, acct, &securestorage.StorageManifest{Version: 1},
		[]*securestorage.StorageItem{item("x", "1"), item("y", "2")}, nil, false)
	if err != nil {
		t.Fatalf("write v1: %v", err)
	}

	// v2 deletes x, inserts z.
	_, err = m.Write(ctx, acct, &securestorage.StorageManifest{Version: 2},
		[]*securestorage.StorageItem{item("z", "3")}, [][]byte{[]byte("x")}, false)
	if err != nil {
		t.Fatalf("write v2: %v", err)
	}

	items, _ := m.Read(ctx, acct, [][]byte{[]byte("x"), []byte("y"), []byte("z")})
	if len(items) != 2 {
		t.Fatalf("expected y and z (x deleted), got %d items", len(items))
	}
}

func TestSecureStorage_ClearAllWipesItems(t *testing.T) {
	m := newStorageManager()
	ctx := context.Background()
	const acct = "acct-4"

	_, _ = m.Write(ctx, acct, &securestorage.StorageManifest{Version: 1},
		[]*securestorage.StorageItem{item("a", "1"), item("b", "2")}, nil, false)

	// clearAll wipes everything, then inserts a fresh item under v2.
	if _, err := m.Write(ctx, acct, &securestorage.StorageManifest{Version: 2},
		[]*securestorage.StorageItem{item("c", "3")}, nil, true); err != nil {
		t.Fatalf("clearAll write: %v", err)
	}

	items, _ := m.Read(ctx, acct, [][]byte{[]byte("a"), []byte("b"), []byte("c")})
	if len(items) != 1 || !bytes.Equal(items[0].Key, []byte("c")) {
		t.Fatalf("expected only c after clearAll, got %+v", items)
	}
}

func TestSecureStorage_WriteRequiresManifest(t *testing.T) {
	m := newStorageManager()
	if _, err := m.Write(context.Background(), "acct-5", nil, nil, nil, false); err == nil {
		t.Fatal("expected error when write operation has no manifest")
	}
}
