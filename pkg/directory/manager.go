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
	// state is the credential configuration, published as ONE immutable
	// value. Mode and key are a single logical fact and must never be
	// observed out of step: two independent atomics let a rotation publish
	// HMAC mode with no key (issuance fails forever) or a live key under
	// stub mode (issuance quietly hands out random passwords cdsi rejects).
	// A reader takes one Load and sees a consistent pair; a writer swaps a
	// whole new value in, so the last writer to complete is the state that
	// stands.
	//
	// Atomic rather than mutex-guarded because credentials are minted on
	// request goroutines while startup rotates and shutdown wipes; the
	// secret inside carries its own reveal-vs-destroy discipline.
	state atomic.Pointer[secretState]
}

// cloneSecret is SecureString.Clone, indirected so the fail-closed path that
// depends on a protected-memory allocation failure can be exercised. That
// failure cannot be provoked from outside, and the path it guards is the one
// that used to silently downgrade this manager to legacy credentials.
// Production code never reassigns it; same seam as sealSecret in
// pkg/config/secrets.
var cloneSecret = (*secrets.SecureString).Clone

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
	// Clone first and branch on the clone. Testing the caller's secret and
	// cloning it afterwards are two separate reveals of a value the caller
	// still owns: a destroy landing between them yields an unset clone, and
	// this would go on to publish HMAC mode over a key that can never mint.
	// The clone is what the manager keeps, so the clone is what decides.
	// Clone before anything is published, and treat an allocation failure as a
	// failure rather than as an absent secret. Those are different facts: an
	// absent secret selects the legacy stub, while a secret that could not be
	// protected must leave the manager exactly as it was. Conflating them
	// means memory pressure silently downgrades a configured deployment to
	// random-UUID credentials the peer rejects — fail-open, and invisible.
	clone, err := cloneSecret(secret)
	if err != nil {
		// Nothing has been published and nothing displaced, so the currently
		// installed configuration — including a live key — survives intact.
		return err
	}
	next := &secretState{}
	if clone.IsDestroyed() {
		// An unset secret is an explicit request for the legacy stub, not a
		// failure — GetAuthToken goes back to random UUIDs. Nothing to wipe in
		// an unset clone; destroying it keeps the ownership contract total.
		clone.Destroy()
	} else {
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
// stub afterwards: GetAuthToken fails closed with a
// SharedSecretUnavailableError, so a wipe can never be mistaken for a
// successful credential grant.
func (m *DirectoryManager) Destroy() {
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

// GetAuthToken returns CDSI credentials for the given account. With a
// configured shared secret, the password is the HMAC-SHA256 of the
// account UUID under that secret. Without one, a random UUID is returned
// (the legacy stub behaviour for non-CDSI deployments).
//
// Once a secret has been configured, a reveal that fails — the secret was
// destroyed, or the enclave would not open — is a
// SharedSecretUnavailableError, never a fallback to the stub.
func (m *DirectoryManager) GetAuthToken(_ context.Context, accountUUID string) (*DirectoryCredentials, error) {
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
		password, err := secrets.NewSecureStringFromBytes(raw)
		if err != nil {
			return nil, err
		}
		return &DirectoryCredentials{
			Username: accountUUID,
			Password: password,
		}, nil
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
