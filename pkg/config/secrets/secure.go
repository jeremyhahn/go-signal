// Package secrets provides secret resolution and secure in-memory storage
// for configuration values using pluggable resolvers and the shared
// protected-memory abstraction.
package secrets

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// redacted is the sentinel string returned by String() and JSON marshaling
// to prevent accidental secret exposure in logs or serialized output.
const redacted = "[REDACTED]"

// sealSecret is the protected-memory allocator, a variable for fault injection; seals pass context.Background().
var sealSecret = secure.NewSecret

// SecureString holds a secret in the secure package's protected memory, with redacting String/MarshalJSON and YAML binding; call Destroy to wipe it.
// Reveals may run concurrently; Destroy waits for them and later reveals fail. Pass by pointer, never copy.
type SecureString struct {
	mu  sync.RWMutex
	sec *secure.Secret

	// configured records that a value was sealed here, separating never set from set but unavailable; once true it stays true.
	configured bool
}

// NewSecureString seals a credential: empty is *EmptySecretError and allocation failure *SealError; optional values use NewOptionalSecureString.
func NewSecureString(value string) (*SecureString, error) {
	if value == "" {
		return nil, &EmptySecretError{}
	}

	// NewSecret copies src into an enclave and wipes src on return.
	src := []byte(value)
	sec, err := sealSecret(context.Background(), src)
	if err != nil {
		// Wipe rather than retain plaintext the caller believes is
		// protected, then report the failure so the caller can abort.
		secure.Wipe(src)
		return nil, &SealError{Cause: err}
	}
	return &SecureString{sec: sec, configured: true}, nil
}

// NewOptionalSecureString is NewSecureString where empty is legitimate and yields an unset SecureString; not for credentials.
func NewOptionalSecureString(value string) (*SecureString, error) {
	if value == "" {
		return &SecureString{}, nil
	}
	return NewSecureString(value)
}

// MustNewSecureString is NewOptionalSecureString that panics on failure, for tests and fixtures only.
func MustNewSecureString(value string) *SecureString {
	s, err := NewOptionalSecureString(value)
	if err != nil {
		panic("secrets: " + err.Error())
	}
	return s
}

// String implements fmt.Stringer and always returns "[REDACTED]".
func (s *SecureString) String() string {
	return redacted
}

// Reveal returns the value as a Go string, or *UnavailableSecretError when unset, destroyed or unopenable; use it wherever a secret goes on the wire.
func (s *SecureString) Reveal() (string, error) {
	if s == nil {
		return "", &UnavailableSecretError{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sec == nil {
		return "", &UnavailableSecretError{}
	}
	buf, err := s.sec.Open(context.Background())
	if err != nil {
		return "", &UnavailableSecretError{Cause: err}
	}
	defer buf.Destroy()
	var value string
	if err := buf.WithBytes(func(b []byte) error {
		value = string(b)
		return nil
	}); err != nil {
		return "", &UnavailableSecretError{Cause: err}
	}
	return value, nil
}

// Plaintext is Reveal returning "" instead of an error, for optional fields; credential boundaries use Reveal.
func (s *SecureString) Plaintext() string {
	value, err := s.Reveal()
	if err != nil {
		return ""
	}
	return value
}

// Bytes returns a heap copy the caller should zero, or nil when unset or destroyed.
func (s *SecureString) Bytes() []byte {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sec == nil {
		return nil
	}
	buf, err := s.sec.Open(context.Background())
	if err != nil {
		return nil
	}
	defer buf.Destroy()
	out, err := secure.CopyOut(buf)
	if err != nil {
		return nil
	}
	return out
}

// IsAbsent reports whether no value was ever held; unlike IsDestroyed it is false for a configured secret that cannot be opened.
func (s *SecureString) IsAbsent() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.configured
}

// IsDestroyed reports whether the underlying secret has been destroyed
// or was never set (i.e. was created from an empty string).
func (s *SecureString) IsDestroyed() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.sec == nil {
		return true
	}
	// Attempt to open; if it fails the secret has been destroyed.
	buf, err := s.sec.Open(context.Background())
	if err != nil {
		return true
	}
	buf.Destroy()
	return false
}

// Destroy wipes and frees the underlying memory allocation.
// After Destroy, IsDestroyed returns true and Plaintext/Bytes return
// empty values. Calling Destroy more than once is safe.
func (s *SecureString) Destroy() {
	if s == nil {
		return
	}
	// The write lock is what makes this a lifetime boundary rather than a
	// pointer update: it waits for the reveals already in flight, so no
	// reader is holding an open buffer when the enclave goes away.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec == nil {
		return
	}
	s.sec.Destroy()
	s.sec = nil
}

// MarshalJSON always emits "[REDACTED]"; handlers that send the value read it explicitly.
func (s *SecureString) MarshalJSON() ([]byte, error) {
	return json.Marshal(redacted)
}

// UnmarshalYAML implements gopkg.in/yaml.v3.Unmarshaler so that YAML
// configuration loading populates a SecureString directly from a string
// node without requiring a string intermediary in the config struct.
func (s *SecureString) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	// We cannot control Go string internals, so the intermediate `raw`
	// cannot be wiped; the enclave copy is what outlives this call. A YAML
	// key may legitimately be absent or empty, so this is an optional value.
	created, err := NewOptionalSecureString(raw)
	if err != nil {
		return err
	}
	// Replace an existing value under one write lock, wiping the old allocation once the new one is sealed.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec != nil {
		s.sec.Destroy()
	}
	s.sec = created.sec
	// configured follows the decoded value; an empty node leaves the secret unset.
	s.configured = created.configured
	return nil
}
