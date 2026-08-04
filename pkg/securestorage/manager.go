package securestorage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"

	"github.com/google/uuid"
)

// SecureStorageManager mints credentials for the storage-service. Per
// Java's SecureStorageController, the password is
// HMAC-SHA256(sharedSecret, accountUUID) — storage-service validates
// inbound credentials against the same secret.
type SecureStorageManager struct {
	logger       *slog.Logger
	sharedSecret []byte
	// store, when non-nil, enables the real storage-service: manifest and
	// item persistence. When nil the REST layer serves the safe 204 "nothing
	// to sync" stub.
	store ManifestStore
}

// NewSecureStorageManager creates a new SecureStorageManager.
func NewSecureStorageManager(logger *slog.Logger) *SecureStorageManager {
	return &SecureStorageManager{logger: logger}
}

// SetSharedSecret installs the HMAC secret used to mint credentials.
// Empty disables HMAC mode and falls back to random-UUID passwords
// for non-storage-service deployments (legacy stub behaviour).
func (m *SecureStorageManager) SetSharedSecret(secret string) {
	if secret == "" {
		m.sharedSecret = nil
		return
	}
	m.sharedSecret = []byte(secret)
}

// SetManifestStore installs the persistence backend for the storage-service.
// Passing nil (or never calling this) keeps the storage-service disabled and
// the REST layer serves the safe 204 stub.
func (m *SecureStorageManager) SetManifestStore(store ManifestStore) {
	m.store = store
}

// StorageEnabled reports whether a manifest store is configured.
func (m *SecureStorageManager) StorageEnabled() bool { return m.store != nil }

// GetManifest returns the account's current storage manifest, or nil when none
// has been written yet. It errors only on a store failure.
func (m *SecureStorageManager) GetManifest(ctx context.Context, accountUUID string) (*StorageManifest, error) {
	manifest, err := m.store.GetManifest(ctx, accountUUID)
	if err != nil {
		var notFound *ManifestNotFoundError
		if errors.As(err, &notFound) {
			return nil, nil
		}
		return nil, err
	}
	return manifest, nil
}

// Write applies a WriteOperation. The new manifest version must be strictly
// greater than the current one; otherwise the current manifest is returned as
// the conflict (the caller maps this to HTTP 409) and no changes are made.
// clearAll wipes all existing items before applying inserts.
func (m *SecureStorageManager) Write(
	ctx context.Context,
	accountUUID string,
	manifest *StorageManifest,
	inserts []*StorageItem,
	deleteKeys [][]byte,
	clearAll bool,
) (conflict *StorageManifest, err error) {
	if manifest == nil {
		return nil, &InvalidStorageRequestError{Reason: "write operation requires a manifest"}
	}

	current, err := m.GetManifest(ctx, accountUUID)
	if err != nil {
		return nil, err
	}
	if current != nil && manifest.Version <= current.Version {
		return current, nil
	}

	if clearAll {
		if err := m.store.DeleteAll(ctx, accountUUID); err != nil {
			return nil, err
		}
	} else {
		for _, key := range deleteKeys {
			if err := m.store.DeleteItem(ctx, accountUUID, key); err != nil {
				var notFound *StorageItemNotFoundError
				if !errors.As(err, &notFound) {
					return nil, err
				}
			}
		}
	}

	for _, item := range inserts {
		if err := m.store.PutItem(ctx, accountUUID, item); err != nil {
			return nil, err
		}
	}

	if err := m.store.PutManifest(ctx, accountUUID, manifest); err != nil {
		var versionConflict *ManifestVersionConflictError
		if errors.As(err, &versionConflict) {
			// Lost a race with a concurrent write — return the now-current
			// manifest as the conflict.
			cur, getErr := m.GetManifest(ctx, accountUUID)
			if getErr != nil {
				return nil, getErr
			}
			return cur, nil
		}
		return nil, err
	}
	return nil, nil
}

// Read returns the items for the requested keys. Keys with no stored item are
// omitted from the result.
func (m *SecureStorageManager) Read(ctx context.Context, accountUUID string, keys [][]byte) ([]*StorageItem, error) {
	items := make([]*StorageItem, 0, len(keys))
	for _, key := range keys {
		item, err := m.store.GetItem(ctx, accountUUID, key)
		if err != nil {
			var notFound *StorageItemNotFoundError
			if errors.As(err, &notFound) {
				continue
			}
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

// GetAuth returns credentials for the storage-service.
func (m *SecureStorageManager) GetAuth(_ context.Context, accountUUID string) (*StorageCredentials, error) {
	if len(m.sharedSecret) == 0 {
		return &StorageCredentials{Username: accountUUID, Password: uuid.NewString()}, nil
	}
	mac := hmac.New(sha256.New, m.sharedSecret)
	mac.Write([]byte(accountUUID))
	return &StorageCredentials{
		Username: accountUUID,
		Password: hex.EncodeToString(mac.Sum(nil)),
	}, nil
}
