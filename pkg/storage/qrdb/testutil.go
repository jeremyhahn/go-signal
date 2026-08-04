package qrdb

import (
	"context"
	"sort"
	"strings"
	"sync"
)

// FakeKVStore is a minimal in-memory KVStore implementation for unit tests.
// It is safe for concurrent use. Production code must not use this type —
// wire an actual qrdb client instead.
type FakeKVStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewFakeKVStore returns an empty FakeKVStore.
func NewFakeKVStore() *FakeKVStore {
	return &FakeKVStore{data: make(map[string][]byte)}
}

// Put stores a value, overwriting any existing value at the key.
func (f *FakeKVStore) Put(_ context.Context, key string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	f.data[key] = cp
	return nil
}

// Get returns a copy of the stored value, or (nil, nil) when the key is absent.
// This matches qrdb's native contract where missing keys return nil without
// error; callers use getOrNotFound when they need the distinction.
func (f *FakeKVStore) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	v, ok := f.data[key]
	if !ok {
		return nil, nil
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

// Delete removes a key. Deleting a missing key is not an error, matching
// qrdb's idempotent-delete semantics.
func (f *FakeKVStore) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.data, key)
	return nil
}

// Scan iterates every key-value pair whose key has the given prefix, in
// lexicographic order. Iteration stops early if fn returns a non-nil error,
// which is returned to the caller.
func (f *FakeKVStore) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	pairs := f.snapshotPrefix(prefix)
	for _, kv := range pairs {
		if err := fn(kv.key, kv.value); err != nil {
			return err
		}
	}
	return nil
}

// List returns all keys sharing the given prefix, sorted lexicographically.
func (f *FakeKVStore) List(_ context.Context, prefix string) ([]string, error) {
	pairs := f.snapshotPrefix(prefix)
	keys := make([]string, 0, len(pairs))
	for _, kv := range pairs {
		keys = append(keys, kv.key)
	}
	return keys, nil
}

// Exists reports whether a value is stored at the key.
func (f *FakeKVStore) Exists(_ context.Context, key string) (bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.data[key]
	return ok, nil
}

type kvPair struct {
	key   string
	value []byte
}

// snapshotPrefix returns a deterministic, lexicographically sorted snapshot
// of all pairs matching the prefix. Taking a snapshot under the read lock
// lets fn run without holding the lock, avoiding deadlocks if fn re-enters
// the store.
func (f *FakeKVStore) snapshotPrefix(prefix string) []kvPair {
	f.mu.RLock()
	defer f.mu.RUnlock()

	pairs := make([]kvPair, 0)
	for k, v := range f.data {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		cp := make([]byte, len(v))
		copy(cp, v)
		pairs = append(pairs, kvPair{key: k, value: cp})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].key < pairs[j].key })
	return pairs
}
