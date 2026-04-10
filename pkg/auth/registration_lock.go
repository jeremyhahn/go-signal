// Package auth provides authentication primitives for the Signal server.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters following OWASP recommended minimums.
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
const (
	argon2Time    uint32 = 3
	argon2Memory  uint32 = 64 * 1024 // 64 MB
	argon2Threads uint8  = 4
	argon2KeyLen  uint32 = 32
	saltLen              = 16
)

// RegistrationLockHash holds the Argon2id salt and derived key for a
// registration lock PIN. Instances are safe to serialize to JSON and store
// persistently alongside an Account.
type RegistrationLockHash struct {
	// Salt is the random salt used during derivation, base64-encoded.
	Salt string `json:"salt"`
	// Hash is the Argon2id-derived key, base64-encoded.
	Hash string `json:"hash"`
}

// HashRegistrationLock derives an Argon2id hash from pin using a freshly
// generated cryptographic salt. The returned RegistrationLockHash can be
// stored persistently; the original PIN is not recoverable from it.
//
// An error is returned only if the OS entropy source fails.
func HashRegistrationLock(pin string) (*RegistrationLockHash, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, &HashingError{Cause: err}
	}

	pinBytes := []byte(pin)
	raw := argon2.IDKey(pinBytes, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	zeroBytes(pinBytes)
	defer zeroBytes(raw)

	result := &RegistrationLockHash{
		Salt: base64.StdEncoding.EncodeToString(salt),
		Hash: base64.StdEncoding.EncodeToString(raw),
	}

	// Wipe the salt from working memory after encoding.
	zeroBytes(salt)

	return result, nil
}

// Verify re-derives the Argon2id key for pin using the stored salt and
// performs a constant-time comparison against the stored hash. It returns
// true only when the PIN matches exactly.
//
// Verify never returns an error; a mismatch (including corrupt stored data)
// always returns false.
func (h *RegistrationLockHash) Verify(pin string) bool {
	salt, err := base64.StdEncoding.DecodeString(h.Salt)
	if err != nil {
		return false
	}
	defer zeroBytes(salt)

	expected, err := base64.StdEncoding.DecodeString(h.Hash)
	if err != nil {
		return false
	}
	defer zeroBytes(expected)

	pinBytes := []byte(pin)
	derived := argon2.IDKey(pinBytes, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	zeroBytes(pinBytes)
	defer zeroBytes(derived)

	return subtle.ConstantTimeCompare(derived, expected) == 1
}

// zeroBytes overwrites every element of b with zero. It is used to wipe
// sensitive key material from memory after use.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// MarshalJSON implements json.Marshaler. Fields are already base64 strings so
// the default struct encoding is used directly.
func (h *RegistrationLockHash) MarshalJSON() ([]byte, error) {
	type plain RegistrationLockHash
	return json.Marshal((*plain)(h))
}

// UnmarshalJSON implements json.Unmarshaler.
func (h *RegistrationLockHash) UnmarshalJSON(data []byte) error {
	type plain RegistrationLockHash
	return json.Unmarshal(data, (*plain)(h))
}
