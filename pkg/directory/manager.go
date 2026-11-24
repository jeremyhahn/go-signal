package directory

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// DirectoryManager manages contact discovery (CDSI) credentials. The
// credential format is HMAC-SHA256(sharedSecret, accountUUID) hex —
// the same scheme svr2 and registration-service use. cmd/cdsi
// validates inbound credentials against the same shared secret.
// The secret lives in protected memory for the process lifetime and is
// revealed only for the length of a single HMAC computation.
type DirectoryManager struct {
	logger *slog.Logger
	// state is mode and key published as one immutable value, so readers never see them out of step.
	state atomic.Pointer[secretState]
}

// cloneSecret is SecureString.Clone, a variable for fault injection.
var cloneSecret = (*secrets.SecureString).CloneWithPresence

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

// NewDirectoryManager creates a new DirectoryManager. When secret is
// empty the manager falls back to random UUIDs so non-CDSI deployments
// can keep using the legacy /v2/directory/auth stub.
func NewDirectoryManager(logger *slog.Logger) *DirectoryManager {
	return &DirectoryManager{logger: logger}
}

// SetSharedSecret installs the HMAC secret used to mint credentials.
// Called by cmd/signald at startup with cfg.CDSI.SharedSecret. The secret
// is cloned into an enclave the manager owns; the caller keeps ownership of
// what it passed in.
//
// Any secret already installed is wiped before being replaced, so a rotation
// leaves no copy of the superseded key resident.
//
// Returns an error only when the secret exists but could not be placed in
// protected memory. That case leaves the manager untouched — the previously
// installed configuration, key included, survives — and callers must treat it
// as fatal rather than proceeding: continuing would run with GetAuthToken's legacy
// stub, issuing random credentials the peer rejects. An absent secret is not
// an error; it selects the stub deliberately.
func (m *DirectoryManager) SetSharedSecret(secret *secrets.SecureString) error {
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
// stub afterwards: GetAuthToken fails closed with a
// SharedSecretUnavailableError, so a wipe can never be mistaken for a
// successful credential grant. A manager that was never configured keeps
// serving the random-UUID stub after Destroy, deliberately: there is no key to
// protect, and failing closed there would turn shutdown into an outage for
// non-CDSI deployments in exchange for nothing.
func (m *DirectoryManager) Destroy() {
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

// GetAuthToken returns CDSI credentials for the given account. With a
// configured shared secret, the password is the HMAC-SHA256 of the
// account UUID under that secret. Without one, a random UUID is returned
// (the legacy stub behavior for non-CDSI deployments).
//
// Once a secret has been configured, a reveal that fails — the secret was
// destroyed, or the enclave would not open — is a
// SharedSecretUnavailableError, never a fallback to the stub.
func (m *DirectoryManager) GetAuthToken(_ context.Context, accountUUID string) (*DirectoryCredentials, error) {
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
		password, err := secrets.NewSecureStringFromBytes(raw)
		if err != nil {
			return nil, err
		}
		return &DirectoryCredentials{
			Username: accountUUID,
			Password: password,
		}, nil
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
	password, err := secrets.NewSecureStringFromBytes(derived)
	if err != nil {
		return nil, err
	}
	return &DirectoryCredentials{
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
