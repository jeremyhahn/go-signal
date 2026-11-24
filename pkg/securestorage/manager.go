package securestorage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// SecureStorageManager issues storage-service credentials: HMAC-SHA256(sharedSecret, accountUUID), the secret revealed only per computation.
type SecureStorageManager struct {
	logger *slog.Logger
	// state is mode and key published as one immutable value, so readers never see them out of step.
	state atomic.Pointer[secretState]
	// store enables manifest and item persistence; nil serves the 204 stub.
	store ManifestStore
}

// cloneSecret is SecureString.Clone, a variable for fault injection.
var cloneSecret = (*secrets.SecureString).CloneWithPresence

// Credential sealing, variables for fault injection.
var (
	newSecureStringBytes = secrets.NewSecureStringFromBytes
)

// secretState is the manager's credential configuration at an instant. It is
// immutable once published: mutating one requires building a replacement and
// swapping it in.
type secretState struct {
	// hmac records that a shared secret was configured; it survives Destroy so issuance fails closed.
	hmac bool
	// secret is the manager's own clone, nil in stub mode and after Destroy.
	secret *secrets.SecureString
	// destroyed marks the terminal state; no state carrying it is replaced.
	destroyed bool
}

// NewSecureStorageManager creates a new SecureStorageManager.
func NewSecureStorageManager(logger *slog.Logger) *SecureStorageManager {
	return &SecureStorageManager{logger: logger}
}

// SetSharedSecret installs a clone of secret, wiping any previous one; an unset secret selects random-UUID stub credentials.
// It errors, leaving the manager unchanged, when the secret exists but cannot be protected; callers treat that as fatal.
func (m *SecureStorageManager) SetSharedSecret(secret *secrets.SecureString) error {
	// Never configured selects the stub; configured and usable selects HMAC; anything else errors. Presence and copy come from one snapshot.
	clone, configured, err := cloneSecret(secret)
	if err != nil {
		// Nothing has been published and nothing displaced, so the currently
		// installed configuration — including a live key — survives intact.
		return err
	}
	next := &secretState{}
	if !configured {
		// Absent (not merely unopenable) selects the stub.
		clone.Destroy()
	} else {
		// The clone must open before HMAC mode is published over it.
		if err := clone.TryWithBytes(func([]byte) {}); err != nil {
			clone.Destroy()
			return err
		}
		next.hmac = true
		next.secret = clone
	}
	// Publish mode and key together by compare-and-swap; losing to Destroy wipes our clone and fails.
	for {
		old := m.state.Load()
		if old != nil && old.destroyed {
			next.secret.Destroy()
			return &ManagerDestroyedError{}
		}
		if m.state.CompareAndSwap(old, next) {
			if old != nil {
				old.secret.Destroy()
			}
			return nil
		}
	}
}

// Destroy wipes the secret and makes the manager terminal; idempotent. A configured manager then fails closed, an unconfigured one keeps the stub.
func (m *SecureStorageManager) Destroy() {
	if m == nil {
		return
	}
	// Compare-and-swap carrying the current hmac flag forward; the terminal state is published even when nothing is installed.
	for {
		old := m.state.Load()
		if old != nil && old.destroyed {
			return
		}
		next := &secretState{destroyed: true}
		if old != nil {
			next.hmac = old.hmac
		}
		if m.state.CompareAndSwap(old, next) {
			if old != nil {
				old.secret.Destroy()
			}
			return
		}
	}
}

// SetManifestStore sets the storage backend; nil leaves the storage-service disabled.
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

// Write applies a WriteOperation if its manifest version is greater than the current one, else returns the current manifest as the conflict (409); clearAll removes items first.
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

// GetAuth returns storage-service credentials: HMAC when configured, else a random UUID; a failed reveal is SharedSecretUnavailableError.
func (m *SecureStorageManager) GetAuth(_ context.Context, accountUUID string) (*StorageCredentials, error) {
	// One Load: mode and key from the same state.
	st := m.state.Load()
	if st == nil || !st.hmac {
		// MarshalText yields the UUID as bytes; uuid.NewString would stage the
		// stub bearer credential in a Go string that cannot be wiped, which is
		// the same exposure the HMAC path below avoids.
		raw, err := uuid.New().MarshalText()
		if err != nil {
			return nil, err
		}
		password, err := newSecureStringBytes(raw)
		if err != nil {
			return nil, err
		}
		return &StorageCredentials{Username: accountUUID, Password: password}, nil
	}
	// Build the credential as bytes and seal it with NewSecureStringFromBytes, which wipes the slice.
	var derived []byte
	if !st.secret.WithBytes(func(key []byte) {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(accountUUID))
		sum := mac.Sum(nil)
		derived = make([]byte, hex.EncodedLen(len(sum)))
		hex.Encode(derived, sum)
		wipe(sum)
	}) {
		return nil, &SharedSecretUnavailableError{AccountUUID: accountUUID}
	}
	password, err := newSecureStringBytes(derived)
	if err != nil {
		return nil, err
	}
	return &StorageCredentials{
		Username: accountUUID,
		Password: password,
	}, nil
}

// wipe zeroes an intermediate slice that held credential material. The
// finished credential is sealed by NewSecureStringFromBytes, which wipes what
// it consumes; this covers the working buffers on the way there.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
