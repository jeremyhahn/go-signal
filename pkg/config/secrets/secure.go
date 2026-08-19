// Package secrets provides secret resolution and secure in-memory storage
// for configuration values using pluggable resolvers and the shared
// protected-memory abstraction.
package secrets

import (
	"encoding/json"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// redacted is the sentinel string returned by String() and JSON marshaling
// to prevent accidental secret exposure in logs or serialized output.
const redacted = "[REDACTED]"

// sealSecret is the protected-memory allocator. It is a variable rather than
// a direct call so the fail-closed paths that depend on an allocation failure
// can be exercised by fault injection; production code never reassigns it.
var sealSecret = secure.NewSecret

// SecureString holds sensitive string data in the shared protected-memory
// abstraction (go-qrdb's secure package, re-exported by the go-xkms SDK as
// github.com/jeremyhahn/go-xkms/sdk/go/secure). The value is sealed in an
// enclave that is guarded against swapping and cross-process reads, and is
// only materialised transiently by Plaintext/Bytes. Call Destroy when the
// value is no longer needed to wipe and free the allocation.
//
// This type owns no protected-memory mechanics of its own: allocation,
// locking, sealing and wiping all live in the upstream secure package. What
// SecureString adds is the go-signal-specific surface — redaction on
// String/MarshalJSON and YAML config binding — so it integrates transparently
// with logging, JSON serialization, and YAML config loading.
//
// The String() method intentionally returns "[REDACTED]" to prevent
// accidental exposure in structured log output. Use Plaintext() or
// Bytes() to access the actual value.
type SecureString struct {
	sec *secure.Secret
}

// NewSecureString seals value in protected memory. It is the constructor for
// credential material: an empty value is rejected with *EmptySecretError and a
// failure to obtain a protected allocation is reported as *SealError, so a
// caller that cannot place a secret in protected memory fails closed instead
// of continuing with an unset value. Configuration values whose absence is
// legitimate use NewOptionalSecureString instead.
//
// The intermediate byte slice is consumed by the secure package, which wipes
// it before returning, so plaintext lives in unprotected memory only for the
// duration of the copy.
func NewSecureString(value string) (*SecureString, error) {
	if value == "" {
		return nil, &EmptySecretError{}
	}

	// NewSecret copies src into an enclave and wipes src on return.
	src := []byte(value)
	sec, err := sealSecret(src)
	if err != nil {
		// Wipe rather than retain plaintext the caller believes is
		// protected, then report the failure so the caller can abort.
		secure.Wipe(src)
		return nil, &SealError{Cause: err}
	}
	return &SecureString{sec: sec}, nil
}

// NewOptionalSecureString is NewSecureString for values whose absence is
// legitimate — an unset optional configuration field, an environment variable
// deliberately exported empty. An empty value yields an unset SecureString
// (Plaintext returns "", IsDestroyed reports true) rather than an error. Any
// other failure is still reported, so this is never a fail-open path.
//
// Credential material must not use this constructor: an issued credential is
// never legitimately empty, and NewSecureString's *EmptySecretError is what
// keeps an empty password from reaching a client.
func NewOptionalSecureString(value string) (*SecureString, error) {
	if value == "" {
		return &SecureString{}, nil
	}
	return NewSecureString(value)
}

// MustNewSecureString is NewOptionalSecureString for call sites that cannot
// act on a failure — tests and fixtures. It panics if the value cannot be
// sealed. Production code paths must use NewSecureString or
// NewOptionalSecureString and propagate the error.
func MustNewSecureString(value string) *SecureString {
	s, err := NewOptionalSecureString(value)
	if err != nil {
		panic("secrets: " + err.Error())
	}
	return s
}

// String implements fmt.Stringer and always returns "[REDACTED]" to prevent
// accidental logging of sensitive values. Use Plaintext() to access the
// underlying value.
func (s *SecureString) String() string {
	return redacted
}

// Reveal opens the enclave, copies the bytes into a regular Go string, and
// destroys the temporary protected buffer immediately. An unset, destroyed or
// unopenable secret is reported as *UnavailableSecretError.
//
// Every boundary that puts a secret on the wire — a credential a client is
// the bearer of, an upstream Authorization header — must use Reveal, so that
// a secret which is not available fails the operation instead of being
// serialised as an empty value the peer would treat as valid.
func (s *SecureString) Reveal() (string, error) {
	if s == nil || s.sec == nil {
		return "", &UnavailableSecretError{}
	}
	buf, err := s.sec.Open()
	if err != nil {
		return "", &UnavailableSecretError{Cause: err}
	}
	defer buf.Destroy()
	return string(buf.Bytes()), nil
}

// Plaintext is Reveal for call sites that already treat an absent secret as
// "not configured" — an optional config field, a presence check. It returns
// an empty string where Reveal returns an error. Credential boundaries must
// use Reveal instead.
func (s *SecureString) Plaintext() string {
	value, err := s.Reveal()
	if err != nil {
		return ""
	}
	return value
}

// Bytes opens the enclave and returns a copy of the raw bytes.
// The returned slice is a plain heap allocation — callers should zero it
// when done. Returns nil if the SecureString has been destroyed or was
// never set.
func (s *SecureString) Bytes() []byte {
	if s == nil || s.sec == nil {
		return nil
	}
	buf, err := s.sec.Open()
	if err != nil {
		return nil
	}
	defer buf.Destroy()
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

// IsDestroyed reports whether the underlying secret has been destroyed
// or was never set (i.e. was created from an empty string).
func (s *SecureString) IsDestroyed() bool {
	if s == nil || s.sec == nil {
		return true
	}
	// Attempt to open; if it fails the secret has been destroyed.
	buf, err := s.sec.Open()
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
	if s == nil || s.sec == nil {
		return
	}
	s.sec.Destroy()
	s.sec = nil
}

// MarshalJSON implements encoding/json.Marshaler and always serialises as
// the JSON string "[REDACTED]" to prevent secret exposure in API responses
// or debug output. Handlers that must put the value on the wire — the
// external-service credentials clients are issued, for example — read it
// explicitly with Plaintext() at the response boundary.
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
	// Decoding into a SecureString that already holds a value replaces it;
	// wipe the previous allocation rather than abandoning it, and only once
	// the replacement is in hand.
	s.Destroy()
	s.sec = created.sec
	return nil
}
