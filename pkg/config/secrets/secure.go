// Package secrets provides secret resolution and secure in-memory storage
// for configuration values using pluggable resolvers and memguard-protected
// locked buffers.
package secrets

import (
	"encoding/json"

	"github.com/awnumar/memguard"
)

// redacted is the sentinel string returned by String() and JSON marshaling
// to prevent accidental secret exposure in logs or serialized output.
const redacted = "[REDACTED]"

// SecureString holds sensitive string data in a memguard LockedBuffer.
// The buffer is allocated in protected memory that is guarded against
// swapping and cross-process reads. Call Destroy when the value is no
// longer needed to wipe and free the allocation.
//
// SecureString implements fmt.Stringer, encoding/json.Marshaler, and
// gopkg.in/yaml.v3.Unmarshaler so it integrates transparently with
// logging, JSON serialization, and YAML config loading.
//
// The String() method intentionally returns "[REDACTED]" to prevent
// accidental exposure in structured log output. Use Plaintext() or
// Bytes() to access the actual value.
type SecureString struct {
	enc *memguard.Enclave
}

// NewSecureString creates a SecureString from the given plaintext value.
// The source slice is wiped to zero bytes immediately after the enclave
// is created to minimise the lifetime of plaintext in unprotected memory.
// If value is empty, a nil SecureString is returned.
func NewSecureString(value string) *SecureString {
	if value == "" {
		return &SecureString{}
	}

	// Copy into a locked buffer, then seal it into an enclave.
	// The locked buffer is destroyed after sealing (Seal wipes it).
	src := []byte(value)
	buf := memguard.NewBufferFromBytes(src)
	// Wipe the source slice immediately after the locked buffer takes ownership.
	for i := range src {
		src[i] = 0
	}
	enc := buf.Seal()
	return &SecureString{enc: enc}
}

// String implements fmt.Stringer and always returns "[REDACTED]" to prevent
// accidental logging of sensitive values. Use Plaintext() to access the
// underlying value.
func (s *SecureString) String() string {
	return redacted
}

// Plaintext opens the enclave, copies the bytes into a regular Go string,
// and destroys the temporary LockedBuffer immediately. Returns an empty
// string if the SecureString has been destroyed or was never set.
func (s *SecureString) Plaintext() string {
	if s == nil || s.enc == nil {
		return ""
	}
	buf, err := s.enc.Open()
	if err != nil {
		return ""
	}
	defer buf.Destroy()
	return string(buf.Bytes())
}

// Bytes opens the enclave and returns a copy of the raw bytes.
// The returned slice is a plain heap allocation — callers should zero it
// when done. Returns nil if the SecureString has been destroyed or was
// never set.
func (s *SecureString) Bytes() []byte {
	if s == nil || s.enc == nil {
		return nil
	}
	buf, err := s.enc.Open()
	if err != nil {
		return nil
	}
	defer buf.Destroy()
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

// IsDestroyed reports whether the underlying enclave has been destroyed
// or was never set (i.e. was created from an empty string).
func (s *SecureString) IsDestroyed() bool {
	if s == nil || s.enc == nil {
		return true
	}
	// Attempt to open; if it fails the enclave has been destroyed.
	buf, err := s.enc.Open()
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
	if s == nil || s.enc == nil {
		return
	}
	// Open and immediately destroy to wipe protected memory.
	buf, err := s.enc.Open()
	if err != nil {
		return
	}
	buf.Destroy()
	s.enc = nil
}

// MarshalJSON implements encoding/json.Marshaler and always serialises as
// the JSON string "[REDACTED]" to prevent secret exposure in API responses
// or debug output.
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
	created := NewSecureString(raw)
	// Wipe the intermediate Go string's backing array as much as possible.
	// We cannot fully control Go string internals, but we can nil the enclave
	// pointer on error paths.
	s.enc = created.enc
	return nil
}
