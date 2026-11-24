package securestorage

import "context"

// StorageManifest is an account's encrypted storage manifest: opaque client bytes and a monotonic version.
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

	// PutManifest stores manifest if its version exceeds the stored one (or is 1 on an empty store), else *ManifestVersionConflictError.
	PutManifest(ctx context.Context, accountUUID string, manifest *StorageManifest) error

	// GetItem retrieves a storage item by key for the given account UUID.
	// Returns *StorageItemNotFoundError when the key does not exist.
	GetItem(ctx context.Context, accountUUID string, key []byte) (*StorageItem, error)

	// PutItem stores or replaces an item for the account.
	PutItem(ctx context.Context, accountUUID string, item *StorageItem) error

	// DeleteItem removes a stored item by key. Returns
	// *StorageItemNotFoundError when the key does not exist.
	DeleteItem(ctx context.Context, accountUUID string, key []byte) error

	// DeleteAll removes all manifests and items for the given account UUID.
	DeleteAll(ctx context.Context, accountUUID string) error
}
