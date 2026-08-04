package qrdb

import (
	"context"
	"errors"
	"testing"
)

func TestFakeKVStore_List_Sorted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()

	_ = kv.Put(ctx, "account:_primary:b", []byte("2"))
	_ = kv.Put(ctx, "account:_primary:a", []byte("1"))
	_ = kv.Put(ctx, "account:_primary:c", []byte("3"))
	_ = kv.Put(ctx, "other:x", []byte("irrelevant"))

	keys, err := kv.List(ctx, "account:_primary:")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("List returned %d keys, want 3: %v", len(keys), keys)
	}
	// Results must be sorted so callers can rely on deterministic ordering.
	for i := 0; i < len(keys)-1; i++ {
		if keys[i] >= keys[i+1] {
			t.Fatalf("List not sorted: %v", keys)
		}
	}
}

func TestFakeKVStore_List_EmptyPrefix_MatchesAll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()

	_ = kv.Put(ctx, "a", []byte("1"))
	_ = kv.Put(ctx, "b", []byte("2"))

	keys, err := kv.List(ctx, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %v", keys)
	}
}

func TestFakeKVStore_Scan_VisitsAllInOrder(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()

	_ = kv.Put(ctx, "p:3", []byte("c"))
	_ = kv.Put(ctx, "p:1", []byte("a"))
	_ = kv.Put(ctx, "p:2", []byte("b"))

	var visited []string
	err := kv.Scan(ctx, "p:", func(k string, v []byte) error {
		visited = append(visited, k+"="+string(v))
		return nil
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(visited) != 3 {
		t.Fatalf("Scan visited %d entries, want 3: %v", len(visited), visited)
	}
	if visited[0] != "p:1=a" || visited[1] != "p:2=b" || visited[2] != "p:3=c" {
		t.Fatalf("Scan did not visit in key order: %v", visited)
	}
}

func TestFakeKVStore_Scan_StopsOnError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()

	_ = kv.Put(ctx, "p:1", []byte("a"))
	_ = kv.Put(ctx, "p:2", []byte("b"))
	_ = kv.Put(ctx, "p:3", []byte("c"))

	stop := errors.New("stop")
	count := 0
	err := kv.Scan(ctx, "p:", func(k string, v []byte) error {
		count++
		if count == 2 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) {
		t.Fatalf("Scan did not propagate sentinel error: %v", err)
	}
	if count != 2 {
		t.Fatalf("Scan visited %d entries after stop, want 2", count)
	}
}

func TestFakeKVStore_Get_ReturnsNilForMissing(t *testing.T) {
	t.Parallel()
	kv := NewFakeKVStore()

	v, err := kv.Get(context.Background(), "missing")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if v != nil {
		t.Fatalf("expected nil value for missing key, got %v", v)
	}
}

func TestFakeKVStore_Get_ReturnsIndependentCopy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()

	_ = kv.Put(ctx, "k", []byte("original"))

	first, _ := kv.Get(ctx, "k")
	first[0] = 'X' // mutate caller's copy

	second, _ := kv.Get(ctx, "k")
	if string(second) != "original" {
		t.Fatalf("Get returned shared buffer; mutations leaked: %s", second)
	}
}

func TestFakeKVStore_Put_ReturnsIndependentCopy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()

	value := []byte("original")
	_ = kv.Put(ctx, "k", value)
	value[0] = 'X' // mutate caller's buffer after Put

	got, _ := kv.Get(ctx, "k")
	if string(got) != "original" {
		t.Fatalf("Put retained caller's buffer reference; mutations leaked: %s", got)
	}
}
