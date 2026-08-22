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
	// state is the credential configuration, published as ONE immutable
	// value. Mode and key are a single logical fact and must never be
	// observed out of step: two independent atomics let a rotation publish
	// HMAC mode with no key (issuance fails forever) or a live key under
	// stub mode (issuance quietly hands out random passwords the
	// storage-service rejects). A reader takes one Load and sees a
	// consistent pair; a writer swaps a whole new value in, so the last
	// writer to complete is the state that stands.
	//
	// Atomic rather than mutex-guarded because credentials are minted on
	// request goroutines while startup rotates and shutdown wipes; the
	// secret inside carries its own reveal-vs-destroy discipline.
	state atomic.Pointer[secretState]
	// store, when non-nil, enables the real storage-service: manifest and
	// item persistence. When nil the REST layer serves the safe 204 "nothing
	// to sync" stub.
	store ManifestStore
}

// cloneSecret is SecureString.Clone, indirected so the fail-closed path that
// depends on a protected-memory allocation failure can be exercised. That
// failure cannot be provoked from outside, and the path it guards is the one
// that used to silently downgrade this manager to legacy credentials.
// Production code never reassigns it; same seam as sealSecret in
// pkg/config/secrets.
var cloneSecret = (*secrets.SecureString).CloneWithPresence

// Credential sealing, indirected for the same reason as cloneSecret: a
// protected-memory allocation failure cannot be provoked from outside, and the
// branches it guards are the ones that must not hand back a credential with no
// password. Production code never reassigns these.
var (
	newSecureStringBytes = secrets.NewSecureStringFromBytes
)

// secretState is the manager's credential configuration at an instant. It is
// immutable once published: mutating one requires building a replacement and
// swapping it in.
type secretState struct {
	// hmac records that a shared secret was configured. It stays true across
	// Destroy, which is what separates "this deployment runs the legacy
	// random-UUID stub" from "the key we were minting with is gone" — the
	// second must fail closed rather than hand back a plausible password.
	hmac bool
	// secret is the manager's own clone, nil in stub mode and after Destroy.
	secret *secrets.SecureString
}

// NewSecureStorageManager creates a new SecureStorageManager.
func NewSecureStorageManager(logger *slog.Logger) *SecureStorageManager {
	return &SecureStorageManager{logger: logger}
}

// SetSharedSecret installs the HMAC secret used to mint credentials.
// An unset secret disables HMAC mode and falls back to random-UUID
// passwords for non-storage-service deployments (legacy stub behaviour).
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
	// Three outcomes have to stay distinct here, and only one of them may
	// select the legacy stub:
	//
	//   never configured   -> stub mode, deliberately
	//   configured, usable -> HMAC mode
	//   configured, not usable, or unclonable -> error, manager untouched
	//
	// Presence and the copy come from ONE snapshot. Asking IsAbsent() and
	// then cloning are two separate reveals: a secret installed between them
	// yields absent=true beside a clone holding a real value, and the stub
	// would be published over a key that exists. Nor can presence be read
	// off the clone — a clone of a configured-but-unrevealable secret is
	// empty, exactly like a clone of an unset one, so that turns "the key
	// will not open" into "there is no key". Both mistakes are fail-open and
	// invisible: every credential minted afterwards is a random UUID the
	// peer rejects.
	//
	// Usability is then asked of the clone, because the clone is what the
	// manager keeps and mints with. Publishing HMAC mode over a key that
	// cannot open is the same fail-open wearing different clothes.
	//
	// Nothing is published until both questions are answered, so an error
	// leaves the previously installed configuration — key included — intact.
	clone, configured, err := cloneSecret(secret)
	if err != nil {
		// Nothing has been published and nothing displaced, so the currently
		// installed configuration — including a live key — survives intact.
		return err
	}
	next := &secretState{}
	if !configured {
		// An unset secret is an explicit request for the legacy stub, not a
		// failure — GetAuth goes back to random UUIDs. Nothing to wipe in an
		// unset clone; destroying it keeps the ownership contract total.
		//
		// IsAbsent, not IsDestroyed: the latter also reports true for a
		// configured secret whose enclave will not open, and taking this
		// branch on that would replace a real installed key with random-UUID
		// credentials the peer rejects. A configured-but-unopenable secret is
		// a failure, handled below.
		clone.Destroy()
	} else {
		// Prove the clone can actually be opened before publishing HMAC mode
		// over it. Publishing a key that cannot mint is the same fail-open in
		// a different disguise: the mode says "authenticated" and every token
		// it issues is unusable.
		if err := clone.TryWithBytes(func([]byte) {}); err != nil {
			clone.Destroy()
			return err
		}
		next.hmac = true
		next.secret = clone
	}
	// One swap publishes mode and key together, so no reader can catch the
	// transition half-applied and no two concurrent rotations can interleave
	// into a mixture of both. Whatever this call displaced is wiped exactly
	// once, by the call that displaced it.
	if old := m.state.Swap(next); old != nil {
		old.secret.Destroy()
	}
	return nil
}

// Destroy wipes the manager's copy of the shared secret. Called from the
// daemon's shutdown path. Safe to call more than once.
//
// A manager that was minting HMAC credentials does not revert to the legacy
// stub afterwards: GetAuth fails closed with a SharedSecretUnavailableError,
// so a wipe can never be mistaken for a successful credential grant.
func (m *SecureStorageManager) Destroy() {
	if m == nil {
		return
	}
	// Compare-and-swap rather than a plain swap: the replacement has to carry
	// the CURRENT hmac flag forward, so it must be built from the state being
	// replaced. Retrying on a lost race is correct — a rotation that landed
	// in between is the newer configuration, and this wipes that one instead.
	for {
		old := m.state.Load()
		if old == nil || old.secret == nil {
			return
		}
		if m.state.CompareAndSwap(old, &secretState{hmac: old.hmac}) {
			old.secret.Destroy()
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
// shared secret a random UUID is returned (the legacy stub behaviour).
//
// Once a secret has been configured, a reveal that fails — the secret was
// destroyed, or the enclave would not open — is a
// SharedSecretUnavailableError, never a fallback to the stub.
func (m *SecureStorageManager) GetAuth(_ context.Context, accountUUID string) (*StorageCredentials, error) {
	// One Load: mode and key come from the same published state, so the
	// branch below cannot be taken against a configuration that no longer
	// exists.
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
	// The credential is assembled as bytes and sealed from them.
	// hex.EncodeToString would put the finished password in a Go string,
	// which the runtime may copy and which cannot be wiped;
	// NewSecureStringFromBytes consumes and wipes the slice instead.
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
