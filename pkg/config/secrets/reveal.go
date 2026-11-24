package secrets

import (
	"context"
	"crypto/subtle"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// sealProtectedBuffer is indirected so the fail-closed path that depends on a
// sealing failure can be exercised by fault injection. Production code never
// reassigns it; same seam and same reasoning as sealSecret.
var sealProtectedBuffer = secure.NewSecretFromBuffer

// WithBytes runs fn on the mlocked plaintext and wipes it afterwards, even on panic; fn must not keep, mutate or Destroy it.
// Reports whether fn ran; false (nil, unset or destroyed) is an authentication failure.
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
	buf, err := s.sec.Open(context.Background())
	if err != nil {
		return false
	}
	defer buf.Destroy()
	return buf.WithBytes(func(b []byte) error {
		fn(b)
		return nil
	}) == nil
}

// Equals reports, in constant time inside WithBytes, whether the value is exactly want; false when unset, destroyed or unopenable.
func (s *SecureString) Equals(want string) bool {
	var equal bool
	ran := s.WithBytes(func(b []byte) {
		equal = subtle.ConstantTimeCompare(b, []byte(want)) == 1
	})
	return ran && equal
}

// IsEmpty reports whether the value is unreadable or zero-length, without materialising it.
func (s *SecureString) IsEmpty() bool {
	empty := true
	ran := s.WithBytes(func(b []byte) { empty = len(b) == 0 })
	return !ran || empty
}

// NewSecureStringFromBytes seals value without a Go string and wipes it; empty input is *EmptySecretError and allocation failure *SealError.
func NewSecureStringFromBytes(value []byte) (*SecureString, error) {
	if len(value) == 0 {
		return nil, &EmptySecretError{}
	}
	sec, err := sealSecret(context.Background(), value)
	if err != nil {
		// Wipe rather than leave plaintext the caller believes was consumed.
		secure.Wipe(value)
		return nil, &SealError{Cause: err}
	}
	return &SecureString{sec: sec, configured: true}, nil
}

// Clone returns an independent copy in its own protected allocation, never staged on the Go heap.
// A nil, unset or destroyed receiver yields (unset, nil); a sealing failure yields (nil, *SealError), so check the error before emptiness.
func (s *SecureString) Clone() (*SecureString, error) {
	clone, _, err := s.CloneWithPresence()
	return clone, err
}

// CloneWithPresence is Clone plus whether the receiver was ever configured, read under one lock; presence describes the source.
func (s *SecureString) CloneWithPresence() (*SecureString, bool, error) {
	if s == nil {
		return &SecureString{}, false, nil
	}
	// Held across both the presence read and the copy: that is the point.
	s.mu.RLock()
	defer s.mu.RUnlock()

	configured := s.configured
	out, err := s.cloneLocked()
	return out, configured, err
}

// cloneLocked copies between protected pages with the read lock held; the shared body of Clone and CloneWithPresence.
func (s *SecureString) cloneLocked() (*SecureString, error) {
	if s.sec == nil {
		return &SecureString{}, nil
	}
	buf, err := s.sec.Open(context.Background())
	if err != nil {
		// Configured but unopenable. Clone's contract reports this as an
		// empty clone rather than an error; CloneWithPresence's caller
		// distinguishes it via the presence bit.
		return &SecureString{}, nil
	}
	// Sealing consumes buf on every path, failure included.
	sec, err := sealProtectedBuffer(context.Background(), buf)
	if err != nil {
		return nil, &SealError{Cause: err}
	}
	return &SecureString{sec: sec, configured: true}, nil
}

// TryWithBytes is WithBytes returning *AbsentSecretError when nothing was sealed and *UnavailableSecretError when the secret cannot be opened.
func (s *SecureString) TryWithBytes(fn func([]byte)) error {
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
	if s.sec == nil {
		// Configured, then destroyed: unavailable, never absent.
		return &UnavailableSecretError{}
	}
	buf, err := s.sec.Open(context.Background())
	if err != nil {
		return &UnavailableSecretError{Cause: err}
	}
	defer buf.Destroy()
	if err := buf.WithBytes(func(b []byte) error {
		fn(b)
		return nil
	}); err != nil {
		return &UnavailableSecretError{Cause: err}
	}
	return nil
}
