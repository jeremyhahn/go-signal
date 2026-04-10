package store

import (
	"context"
	"sort"
	"strings"
	"sync"
)

// MemoryKVClient is a thread-safe in-memory implementation of KVClient.
// It is suitable for tests and standalone operation.
type MemoryKVClient struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// NewMemoryKVClient returns a new in-memory KVClient.
func NewMemoryKVClient() *MemoryKVClient {
	return &MemoryKVClient{
		data: make(map[string][]byte),
	}
}

// Put stores a value at the given key, overwriting any existing value.
func (m *MemoryKVClient) Put(_ context.Context, key string, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[key] = cp
	return nil
}

// Get retrieves the value stored at the given key.
func (m *MemoryKVClient) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[key]
	if !ok {
		return nil, &KeyNotFoundError{Key: key}
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

// Delete removes the value stored at the given key.
func (m *MemoryKVClient) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.data[key]; !ok {
		return &KeyNotFoundError{Key: key}
	}
	delete(m.data, key)
	return nil
}

// List returns all keys that share the given prefix, sorted lexicographically.
func (m *MemoryKVClient) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// Scan iterates over all key-value pairs whose keys share the given prefix in
// sorted order, invoking fn for each pair. Iteration stops early if fn returns
// an error.
func (m *MemoryKVClient) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	m.mu.RLock()
	var pairs []struct {
		key   string
		value []byte
	}
	for k, v := range m.data {
		if strings.HasPrefix(k, prefix) {
			cp := make([]byte, len(v))
			copy(cp, v)
			pairs = append(pairs, struct {
				key   string
				value []byte
			}{key: k, value: cp})
		}
	}
	m.mu.RUnlock()

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].key < pairs[j].key
	})

	for _, p := range pairs {
		if err := fn(p.key, p.value); err != nil {
			return err
		}
	}
	return nil
}

// Exists reports whether a value is stored at the given key.
func (m *MemoryKVClient) Exists(_ context.Context, key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.data[key]
	return ok, nil
}
