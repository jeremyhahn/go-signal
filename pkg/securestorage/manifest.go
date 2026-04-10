package securestorage

import "context"

// StorageManifest represents a Signal storage service manifest. The manifest
// tracks the set of storage keys that an account has written, along with a
// monotonically increasing version number.
//
// All fields are opaque bytes as received from the client; the server stores
// them without interpretation (end-to-end encrypted).
type StorageManifest struct {
	// Version is the monotonically increasing manifest version.
	Version uint64

	// Value is the encrypted manifest blob supplied by the client.
	Value []byte
}

// StorageItem represents a single encrypted item in the storage service.
type StorageItem struct {
	// Key is the storage item key (opaque, client-chosen).
	Key []byte

	// Value is the encrypted item value.
	Value []byte
}

// ManifestStore defines the persistence interface for storage service manifests
// and items. Implementations must be safe for concurrent use.
type ManifestStore interface {
	// GetManifest retrieves the current manifest for the given account UUID.
	// Returns *ManifestNotFoundError when no manifest has been stored yet.
	GetManifest(ctx context.Context, accountUUID string) (*StorageManifest, error)

	// PutManifest stores a new manifest for the given account UUID. The
	// incoming manifest.Version must be strictly greater than the currently
	// stored version (or the store must be empty for version 1). Returns
	// *ManifestVersionConflictError on a version violation.
	PutManifest(ctx context.Context, accountUUID string, manifest *StorageManifest) error

	// GetItem retrieves a storage item by key for the given account UUID.
	// Returns *StorageItemNotFoundError when the key does not exist.
	GetItem(ctx context.Context, accountUUID string, key []byte) (*StorageItem, error)

	// PutItem stores an item under the given key for the given account UUID,
	// replacing any previously stored value.
	PutItem(ctx context.Context, accountUUID string, item *StorageItem) error

	// DeleteItem removes a stored item by key. Returns
	// *StorageItemNotFoundError when the key does not exist.
	DeleteItem(ctx context.Context, accountUUID string, key []byte) error

	// DeleteAll removes all manifests and items for the given account UUID.
	DeleteAll(ctx context.Context, accountUUID string) error
}
