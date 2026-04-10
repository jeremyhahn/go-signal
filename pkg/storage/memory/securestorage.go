package memory

import (
	"bytes"
	"context"
	"sync"

	"github.com/jeremyhahn/go-signal/pkg/securestorage"
)

// Compile-time interface satisfaction check.
var _ securestorage.ManifestStore = (*MemoryManifestStore)(nil)

// itemKey uniquely identifies a storage item within an account.
type itemKey struct {
	accountUUID string
	keyHex      string // hex-encoded item key for use as a map key
}

// MemoryManifestStore implements securestorage.ManifestStore with in-memory
// maps. All operations are safe for concurrent use.
type MemoryManifestStore struct {
	mu        sync.RWMutex
	manifests map[string]*securestorage.StorageManifest // accountUUID -> manifest
	items     map[itemKey]*securestorage.StorageItem
}

// NewMemoryManifestStore creates a new in-memory manifest store.
func NewMemoryManifestStore() *MemoryManifestStore {
	return &MemoryManifestStore{
		manifests: make(map[string]*securestorage.StorageManifest),
		items:     make(map[itemKey]*securestorage.StorageItem),
	}
}

// GetManifest retrieves the current manifest for the given account UUID.
// Returns *securestorage.ManifestNotFoundError when no manifest exists.
func (s *MemoryManifestStore) GetManifest(_ context.Context, accountUUID string) (*securestorage.StorageManifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, exists := s.manifests[accountUUID]
	if !exists {
		return nil, &securestorage.ManifestNotFoundError{AccountUUID: accountUUID}
	}

	return cloneManifest(m), nil
}

// PutManifest stores a new manifest for the given account UUID. The incoming
// manifest.Version must be strictly greater than the currently stored version.
// Returns *securestorage.ManifestVersionConflictError on a version violation.
func (s *MemoryManifestStore) PutManifest(_ context.Context, accountUUID string, manifest *securestorage.StorageManifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, exists := s.manifests[accountUUID]; exists {
		if manifest.Version <= existing.Version {
			return &securestorage.ManifestVersionConflictError{
				AccountUUID:      accountUUID,
				StoredVersion:    existing.Version,
				SubmittedVersion: manifest.Version,
			}
		}
	}

	s.manifests[accountUUID] = cloneManifest(manifest)
	return nil
}

// GetItem retrieves a storage item by key for the given account UUID.
// Returns *securestorage.StorageItemNotFoundError when the key does not exist.
func (s *MemoryManifestStore) GetItem(_ context.Context, accountUUID string, key []byte) (*securestorage.StorageItem, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ik := itemKey{accountUUID: accountUUID, keyHex: hexKey(key)}
	item, exists := s.items[ik]
	if !exists {
		return nil, &securestorage.StorageItemNotFoundError{AccountUUID: accountUUID, Key: cloneBytes(key)}
	}

	return cloneStorageItem(item), nil
}

// PutItem stores an item under the given key for the given account UUID,
// replacing any previously stored value.
func (s *MemoryManifestStore) PutItem(_ context.Context, accountUUID string, item *securestorage.StorageItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ik := itemKey{accountUUID: accountUUID, keyHex: hexKey(item.Key)}
	s.items[ik] = cloneStorageItem(item)
	return nil
}

// DeleteItem removes a stored item by key. Returns
// *securestorage.StorageItemNotFoundError when the key does not exist.
func (s *MemoryManifestStore) DeleteItem(_ context.Context, accountUUID string, key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ik := itemKey{accountUUID: accountUUID, keyHex: hexKey(key)}
	if _, exists := s.items[ik]; !exists {
		return &securestorage.StorageItemNotFoundError{AccountUUID: accountUUID, Key: cloneBytes(key)}
	}

	delete(s.items, ik)
	return nil
}

// DeleteAll removes all manifests and items for the given account UUID.
func (s *MemoryManifestStore) DeleteAll(_ context.Context, accountUUID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.manifests, accountUUID)

	for k := range s.items {
		if k.accountUUID == accountUUID {
			delete(s.items, k)
		}
	}

	return nil
}

// cloneManifest returns a deep copy of a StorageManifest.
func cloneManifest(m *securestorage.StorageManifest) *securestorage.StorageManifest {
	clone := *m
	clone.Value = cloneBytes(m.Value)
	return &clone
}

// cloneStorageItem returns a deep copy of a StorageItem.
func cloneStorageItem(item *securestorage.StorageItem) *securestorage.StorageItem {
	clone := *item
	clone.Key = cloneBytes(item.Key)
	clone.Value = cloneBytes(item.Value)
	return &clone
}

// hexKey converts a byte-slice key to a hex string for use as a map key.
// Using encoding/hex here would be correct but pulls in an import; instead
// we use a compact inline conversion to keep the hot path allocation-free for
// short keys.
func hexKey(b []byte) string {
	const hexDigits = "0123456789abcdef"
	if len(b) == 0 {
		return ""
	}
	buf := make([]byte, len(b)*2)
	for i, v := range b {
		buf[i*2] = hexDigits[v>>4]
		buf[i*2+1] = hexDigits[v&0xf]
	}
	return string(buf)
}

// bytesEqual is a helper used in tests to compare byte-slice item keys.
func bytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }
