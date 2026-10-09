package secrets

import (
	"context"
	"crypto/subtle"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// Protected-memory allocators, indirected so the fail-closed paths that depend
// on an allocation failure can be exercised by fault injection. Production code
// never reassigns them; same seam and same reasoning as sealSecret.
var (
	newProtectedBuffer  = secure.NewBuffer
	sealProtectedBuffer = secure.NewSecretFromBuffer
)

// WithBytes reveals the protected value for the duration of fn and destroys
// the revealed buffer before returning. The slice handed to fn is the secure
// package's own mlocked, guard-paged memory — no plaintext copy reaches the Go
// heap — and it is wiped on the way out, including when fn panics.
//
// This is the accessor for long-lived key material consumed by a short
// computation: an HMAC over one request, say. It keeps the plaintext resident
// only for that computation. Prefer it over Bytes, which hands back an
// ordinary heap allocation the caller must remember to zero, and over Reveal,
// which produces a Go string that cannot be wiped at all.
//
// fn MUST NOT retain the slice beyond the call and MUST NOT mutate it; the
// backing memory is released as soon as fn returns. fn runs under the
// secret's read lock, so it must not call Destroy on the same SecureString.
//
// Reports whether fn ran. False means the SecureString is nil, was never set,
// or has been destroyed — callers must treat that as a failure to authenticate
// rather than proceeding with an empty key.
func (s *SecureString) WithBytes(ctx context.Context, fn func([]byte)) bool {
	if s == nil || fn == nil {
		return false
	}
	// Held for the whole of fn: a Destroy racing a reveal waits for the
	// computation in flight rather than pulling the pages out from under it,
	// and every reveal after that Destroy fails closed.
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.withMaterialLocked(ctx, fn) == nil
}

// Equals reports whether the protected value is exactly want, without ever
// materialising it as a Go string.
//
// The comparison runs inside WithBytes, so the plaintext stays in the secure
// package's mlocked, guard-paged memory and is wiped on the way out. Plaintext
// would hand back an immutable heap string the runtime is free to copy and
// that can never be zeroed — and its own contract limits it to call sites that
// treat an absent secret as "not configured", which a comparison against a
// known value is not.
//
// This is the accessor for checking a secret against a value that is already
// known: rejecting a shipped placeholder at boot, say. want is an ordinary
// string because it is not secret; only the configured value is.
//
// The byte comparison is constant time. Nothing much leaks by timing when the
// other operand is a public placeholder, but a comparison helper that returns
// early on a mismatch is exactly the one a later caller reuses at a real
// credential boundary.
//
// Reports false when the SecureString is nil, was never set, has been
// destroyed, or cannot be opened: a value that cannot be read is not a value
// that matches. Callers deciding "is this the placeholder" get the safe
// answer, and callers that need to distinguish unreadable from
// different must check IsAbsent/IsDestroyed themselves.
func (s *SecureString) Equals(ctx context.Context, want string) bool {
	var equal bool
	ran := s.WithBytes(ctx, func(b []byte) {
		equal = subtle.ConstantTimeCompare(b, []byte(want)) == 1
	})
	return ran && equal
}

// IsEmpty reports whether the protected value is unreadable or zero-length,
// without materialising it. It is the presence check for a config field whose
// absence means "not configured".
//
// Reading the value through Plaintext to compare it with "" places the whole
// secret on the Go heap as an immutable string merely to learn its length,
// which is the same defect as comparing it there.
func (s *SecureString) IsEmpty(ctx context.Context) bool {
	empty := true
	ran := s.WithBytes(ctx, func(b []byte) { empty = len(b) == 0 })
	return !ran || empty
}

// NewSecureStringFromBytes seals value in protected memory without routing it
// through a Go string, which the runtime is free to copy and which cannot be
// wiped. value is consumed and wiped as the protected allocation takes
// ownership of it; callers must not reuse it afterwards.
//
// Empty input and allocation failure are reported the same way as
// NewSecureString: *EmptySecretError and *SealError respectively, so a caller
// that cannot place a secret in protected memory fails closed.
func NewSecureStringFromBytes(ctx context.Context, value []byte) (*SecureString, error) {
	if len(value) == 0 {
		return nil, &EmptySecretError{}
	}
	sec, err := sealSecret(ctx, value)
	if err != nil {
		// Wipe rather than leave plaintext the caller believes was consumed.
		secure.Wipe(value)
		return nil, &SealError{Cause: err}
	}
	return &SecureString{sec: sec, configured: true}, nil
}

// Clone returns an independent SecureString holding the same value in its own
// protected allocation. Destroying either leaves the other usable.
//
// Use this wherever a component takes ownership of a secret it was handed — a
// manager storing a key drawn from the process configuration, a client keeping
// the HMAC secret it signs with — so that the component's Destroy cannot reach
// back into the caller's copy.
//
// The value never leaves protected memory. A sealed source is opened into a
// fresh mlocked buffer and that buffer is sealed in place; a staged source is
// copied page to page into a freshly allocated one, which is sealed. There is
// deliberately no intermediate Go-heap slice, which would put the raw key in
// ordinary memory the runtime may copy and the allocator may hand out again.
// TestClone_DoesNotStagePlaintextOnTheGoHeap guards this.
//
// The two ways this can fail to produce a key are deliberately NOT the same
// result, because conflating them is a fail-open:
//
//   - A nil, unset or destroyed receiver yields (unset, nil). There is no
//     secret to copy and that is a legitimate configuration — a deployment
//     that runs without one.
//   - An allocation failure yields (nil, *SealError). A secret exists and
//     could not be protected. A caller that reads this as "no secret
//     configured" would silently downgrade a configured deployment under
//     nothing worse than memory pressure, which is why it is an error and not
//     an empty value.
//
// Callers must therefore branch on the error before branching on emptiness.
func (s *SecureString) Clone(ctx context.Context) (*SecureString, error) {
	clone, _, err := s.CloneWithPresence(ctx)
	return clone, err
}

// CloneWithPresence is Clone plus whether the receiver was ever configured,
// both determined under ONE read lock.
//
// Asking the two questions separately — IsAbsent() and then Clone() — is a
// race: a secret installed between the calls yields absent=true alongside a
// clone that holds a real value, and a caller choosing a stub on absence
// would publish stub mode over a key that exists. The manager's whole
// decision has to come from a single snapshot, which is what this provides.
//
// The presence bit describes the SOURCE, not the returned clone: a configured
// secret that could not be revealed yields (unset clone, true, nil), and the
// caller must treat that as a failure rather than as an absent secret. The
// error cases match Clone's.
func (s *SecureString) CloneWithPresence(ctx context.Context) (*SecureString, bool, error) {
	if s == nil {
		return &SecureString{}, false, nil
	}
	// Held across both the presence read and the copy: that is the point.
	s.mu.RLock()
	defer s.mu.RUnlock()

	configured := s.configured
	out, err := s.cloneLocked(ctx)
	return out, configured, err
}

// cloneLocked performs the protected-page copy. The receiver's read lock must
// already be held; it is the shared body of Clone and CloneWithPresence, so
// the two cannot drift apart.
func (s *SecureString) cloneLocked(ctx context.Context) (*SecureString, error) {
	var dst *secure.Buffer
	switch {
	case s.sec != nil:
		buf, err := s.sec.Open(ctx)
		if err != nil {
			// Configured but unopenable. Clone's contract reports this as an
			// empty clone rather than an error; CloneWithPresence's caller
			// distinguishes it via the presence bit.
			return &SecureString{}, nil
		}
		// Open decrypts into a fresh buffer this call owns outright, so that
		// buffer is sealed in place: no second copy of the plaintext is made.
		dst = buf
	case s.staged != nil:
		buf, ok, err := copyProtected(s.staged)
		if err != nil {
			return nil, err
		}
		if !ok {
			// Wiped underneath the read lock by a process-wide sweep: as
			// unopenable as a sealed value that will not Open.
			return &SecureString{}, nil
		}
		dst = buf
	default:
		return &SecureString{}, nil
	}
	sec, err := sealProtectedBuffer(ctx, dst)
	if err != nil {
		// NewSecretFromBuffer consumes dst; Destroy is idempotent.
		dst.Destroy()
		return nil, &SealError{Cause: err}
	}
	return &SecureString{sec: sec, configured: true}, nil
}

// copyProtected copies src into a freshly allocated locked buffer, protected
// page to protected page with no Go-heap staging in between. ok is false when
// src has no readable material left — a process-wide wipe took it — and err
// is *SealError when the destination could not be allocated.
func copyProtected(src *secure.Buffer) (dst *secure.Buffer, ok bool, err error) {
	size := src.Size()
	if size == 0 {
		return nil, false, nil
	}
	dst, err = newProtectedBuffer(size)
	if err != nil {
		return nil, false, &SealError{Cause: err}
	}
	// Two independent buffers, each borrowed under its own lock, so nesting
	// the borrows cannot deadlock. The length check refuses a source a sweep
	// shrank between Size and the borrow rather than sealing zeros.
	copied := false
	_ = src.WithBytes(func(b []byte) error {
		return dst.WithBytes(func(d []byte) error {
			if len(d) == len(b) {
				copied = copy(d, b) == len(b)
			}
			return nil
		})
	})
	if !copied {
		dst.Destroy()
		return nil, false, nil
	}
	return dst, true, nil
}

// TryWithBytes is WithBytes with a fallible result: it distinguishes a secret
// that was never configured from one that is configured but cannot be opened.
//
// WithBytes reports both as a bare false, which is adequate for "authenticate
// or fail" but not for "is this deployment configured". A call site deciding
// between a real key and a stub needs the difference: treating an unopenable
// enclave as absent installs the stub over a key that is actually present.
//
// Returns *AbsentSecretError when nothing was ever sealed here, and
// *UnavailableSecretError when a configured secret could not be opened or has
// been destroyed. fn carries the same contract as in WithBytes: it must not
// retain or mutate the slice, and must not Destroy the same SecureString.
func (s *SecureString) TryWithBytes(ctx context.Context, fn func([]byte)) error {
	if s == nil {
		return &AbsentSecretError{}
	}
	if fn == nil {
		return &UnavailableSecretError{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.configured {
		return &AbsentSecretError{}
	}
	// Configured, then destroyed or unopenable: unavailable, never absent.
	return s.withMaterialLocked(ctx, fn)
}
