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

// DirectoryManager issues CDSI credentials: hex HMAC-SHA256(sharedSecret, accountUUID), the secret revealed only per computation.
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

// NewDirectoryManager returns a DirectoryManager that issues random-UUID stub credentials until a secret is set.
func NewDirectoryManager(logger *slog.Logger) *DirectoryManager {
	return &DirectoryManager{logger: logger}
}

// SetSharedSecret installs a clone of secret, wiping any previous one; an absent secret selects the stub.
// It errors, leaving the manager unchanged, when the secret exists but cannot be protected; callers treat that as fatal.
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

// Destroy wipes the secret and makes the manager terminal; idempotent. A configured manager then fails closed, an unconfigured one keeps the stub.
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

// GetAuthToken returns CDSI credentials: HMAC of the account UUID when configured, else a random UUID; a failed reveal is SharedSecretUnavailableError.
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
