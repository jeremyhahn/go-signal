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

// SecureStorageManager mints credentials for the storage-service. Per
// Java's SecureStorageController, the password is
// HMAC-SHA256(sharedSecret, accountUUID) — storage-service validates
// inbound credentials against the same secret.
// The secret lives in protected memory for the process lifetime and is
// revealed only for the length of a single HMAC computation.
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

// SetSharedSecret installs the HMAC secret used to mint credentials.
// An unset secret disables HMAC mode and falls back to random-UUID
// passwords for non-storage-service deployments (legacy stub behavior).
// The secret is cloned into an enclave the manager owns; the caller keeps
// ownership of what it passed in.
//
// Any secret already installed is wiped before being replaced, so a rotation
// leaves no copy of the superseded key resident.
//
// Returns an error only when the secret exists but could not be placed in
// protected memory. That case leaves the manager untouched — the previously
// installed configuration, key included, survives — and callers must treat it
// as fatal rather than proceeding: continuing would run with GetAuth's legacy
// stub, issuing random credentials the peer rejects. An absent secret is not
// an error; it selects the stub deliberately.
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

// Destroy wipes the manager's copy of the shared secret and makes the manager
// terminal: no later SetSharedSecret can install another one. Called from the
// daemon's shutdown path. Safe to call more than once, and on a manager that
// was never configured.
//
// Terminal is the point. Wiping what is installed at the instant Destroy runs
// says nothing about a SetSharedSecret already in flight, which cloned its
// secret before Destroy started and would publish it after Destroy returned —
// a live protected allocation, installed after shutdown, that nothing would
// ever wipe. The marker is what that setter checks.
//
// A manager that was minting HMAC credentials does not revert to the legacy
// stub afterwards: GetAuth fails closed with a SharedSecretUnavailableError,
// so a wipe can never be mistaken for a successful credential grant. A manager
// that was never configured keeps serving the random-UUID stub after Destroy,
// deliberately: there is no key to protect, and failing closed there would turn
// shutdown into an outage for non-storage-service deployments in exchange for
// nothing.
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

// GetAuth returns credentials for the storage-service. Without a configured
// shared secret a random UUID is returned (the legacy stub behavior).
//
// Once a secret has been configured, a reveal that fails — the secret was
// destroyed, or the enclave would not open — is a
// SharedSecretUnavailableError, never a fallback to the stub.
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
