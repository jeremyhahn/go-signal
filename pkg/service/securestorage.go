package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/securestorage"
)

// SecureStorageService defines the storage-service operations exposed to
// protocol handlers.
type SecureStorageService interface {
	// GetAuth returns credentials for the storage-service for the given
	// account UUID.
	GetAuth(ctx context.Context, accountUUID string) (*securestorage.StorageCredentials, error)

	// StorageEnabled reports whether a manifest store is configured. When
	// false the REST layer serves the safe 204 stub.
	StorageEnabled() bool

	// GetManifest returns the account's current storage manifest, or nil when
	// none has been written.
	GetManifest(ctx context.Context, accountUUID string) (*securestorage.StorageManifest, error)

	// Write applies a write operation, returning the current manifest as a
	// conflict (non-nil) when the submitted version is not strictly greater.
	Write(ctx context.Context, accountUUID string, manifest *securestorage.StorageManifest, inserts []*securestorage.StorageItem, deleteKeys [][]byte, clearAll bool) (*securestorage.StorageManifest, error)

	// Read returns the items for the requested keys (missing keys omitted).
	Read(ctx context.Context, accountUUID string, keys [][]byte) ([]*securestorage.StorageItem, error)
}

// secureStorageService is the default SecureStorageService backed by a
// SecureStorageManager.
type secureStorageService struct {
	manager *securestorage.SecureStorageManager
}

// NewSecureStorageService returns a SecureStorageService that delegates to
// the given SecureStorageManager. The manager must not be nil.
func NewSecureStorageService(manager *securestorage.SecureStorageManager) SecureStorageService {
	return &secureStorageService{manager: manager}
}

func (s *secureStorageService) GetAuth(ctx context.Context, accountUUID string) (*securestorage.StorageCredentials, error) {
	return s.manager.GetAuth(ctx, accountUUID)
}

func (s *secureStorageService) StorageEnabled() bool { return s.manager.StorageEnabled() }

func (s *secureStorageService) GetManifest(ctx context.Context, accountUUID string) (*securestorage.StorageManifest, error) {
	return s.manager.GetManifest(ctx, accountUUID)
}

func (s *secureStorageService) Write(ctx context.Context, accountUUID string, manifest *securestorage.StorageManifest, inserts []*securestorage.StorageItem, deleteKeys [][]byte, clearAll bool) (*securestorage.StorageManifest, error) {
	return s.manager.Write(ctx, accountUUID, manifest, inserts, deleteKeys, clearAll)
}

func (s *secureStorageService) Read(ctx context.Context, accountUUID string, keys [][]byte) ([]*securestorage.StorageItem, error) {
	return s.manager.Read(ctx, accountUUID, keys)
}

// Compile-time assertion: SecureStorageManager must satisfy SecureStorageService.
var _ SecureStorageService = (*securestorage.SecureStorageManager)(nil)
