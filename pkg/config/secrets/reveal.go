package secrets

import "github.com/jeremyhahn/go-qrdb/sdk/go/secure"

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
func (s *SecureString) WithBytes(fn func([]byte)) bool {
	if s == nil || fn == nil {
		return false
	}
	// Held for the whole of fn: a Destroy racing a reveal waits for the
	// computation in flight rather than pulling the pages out from under it,
	// and every reveal after that Destroy fails closed.
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sec == nil {
		return false
	}
	buf, err := s.sec.Open()
	if err != nil {
		return false
	}
	defer buf.Destroy()
	fn(buf.Bytes())
	return true
}

// NewSecureStringFromBytes seals value in protected memory without routing it
// through a Go string, which the runtime is free to copy and which cannot be
// wiped. value is consumed and wiped as the protected allocation takes
// ownership of it; callers must not reuse it afterwards.
//
// Empty input and allocation failure are reported the same way as
// NewSecureString: *EmptySecretError and *SealError respectively, so a caller
// that cannot place a secret in protected memory fails closed.
func NewSecureStringFromBytes(value []byte) (*SecureString, error) {
	if len(value) == 0 {
		return nil, &EmptySecretError{}
	}
	sec, err := sealSecret(value)
	if err != nil {
		// Wipe rather than leave plaintext the caller believes was consumed.
		secure.Wipe(value)
		return nil, &SealError{Cause: err}
	}
	return &SecureString{sec: sec}, nil
}

// Clone returns an independent SecureString holding the same value in its own
// protected allocation. Destroying either leaves the other usable.
//
// Use this wherever a component takes ownership of a secret it was handed — a
// manager storing a key drawn from the process configuration, a client keeping
// the HMAC secret it signs with — so that the component's Destroy cannot reach
// back into the caller's copy.
//
// The value never leaves protected memory. It is copied straight from the
// source's mlocked buffer into a freshly allocated one and that buffer is
// sealed in place; there is deliberately no intermediate Go-heap slice, which
// would put the raw key in ordinary memory the runtime may copy and the
// allocator may hand out again. TestClone_DoesNotStagePlaintextOnTheGoHeap
// guards this.
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
func (s *SecureString) Clone() (*SecureString, error) {
	var (
		out    *SecureString
		sealed error
	)
	revealed := s.WithBytes(func(b []byte) {
		dst, err := newProtectedBuffer(len(b))
		if err != nil {
			sealed = &SealError{Cause: err}
			return
		}
		// dst.Bytes() is the mlocked destination: protected page to
		// protected page, with no Go-heap staging in between.
		copy(dst.Bytes(), b)
		sec, err := sealProtectedBuffer(dst)
		if err != nil {
			dst.Destroy()
			sealed = &SealError{Cause: err}
			return
		}
		out = &SecureString{sec: sec}
	})
	if sealed != nil {
		return nil, sealed
	}
	if !revealed || out == nil {
		// Nothing to copy: the receiver holds no secret.
		return &SecureString{}, nil
	}
	return out, nil
}
