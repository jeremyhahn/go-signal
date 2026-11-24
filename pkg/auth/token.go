package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// saltSize is the length in bytes of the random salt generated for each
	// token hash. 16 bytes provides 128 bits of uniqueness.
	saltSize = 16

	// hashSize is the length in bytes of the derived key output from HKDF.
	// 32 bytes matches SHA-256 output size.
	hashSize = 32

	// hkdfInfo is the HKDF context/info string that domain-separates these
	// derived keys from any other HKDF usage in the codebase.
	hkdfInfo = "Signal-Server-AuthToken-v1"
)

// SaltedTokenHash is a salted HKDF-SHA256 digest of a token, salt and hash as lowercase hex; the token is never persisted.
type SaltedTokenHash struct {
	// Salt is the hex-encoded 16-byte random salt used when deriving Hash.
	Salt string `json:"salt"`

	// Hash is the hex-encoded 32-byte HKDF-SHA256 output derived from the
	// token and Salt.
	Hash string `json:"hash"`
}

// NewSaltedTokenHash derives a 32-byte HKDF-SHA256 hash of token with a random 16-byte salt; an empty token is InvalidTokenError.
func NewSaltedTokenHash(token string) (*SaltedTokenHash, error) {
	if token == "" {
		return nil, &InvalidTokenError{Reason: "token must not be empty"}
	}

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, &TokenHashError{Cause: err}
	}

	// Zero the IKM copy once HKDF has consumed it to minimise the lifetime
	// of plaintext token bytes on the heap.
	ikm := []byte(token)
	hash, err := deriveHash(ikm, salt)
	zeroBytes(ikm)
	if err != nil {
		zeroBytes(salt)
		return nil, err
	}

	result := &SaltedTokenHash{
		Salt: hex.EncodeToString(salt),
		Hash: hex.EncodeToString(hash),
	}

	// Zero raw key material now that it has been hex-encoded into the struct.
	zeroBytes(hash)
	zeroBytes(salt)

	return result, nil
}

// Verify re-derives the hash with the stored salt and compares in constant time; any error returns false. token is neither kept nor modified, so the caller can wipe it.
func (h *SaltedTokenHash) Verify(token []byte) bool {
	if len(token) == 0 || h == nil {
		return false
	}

	salt, err := hex.DecodeString(h.Salt)
	if err != nil {
		return false
	}
	defer zeroBytes(salt)

	storedHash, err := hex.DecodeString(h.Hash)
	if err != nil {
		return false
	}
	defer zeroBytes(storedHash)

	derived, err := deriveHash(token, salt)
	if err != nil {
		return false
	}
	defer zeroBytes(derived)

	return subtle.ConstantTimeCompare(derived, storedHash) == 1
}

// deriveHash runs HKDF-SHA256 with the given token as the IKM, salt as the
// HKDF salt, and the package-level hkdfInfo string as the context label.
// It returns a hashSize-byte output key material slice.
func deriveHash(token, salt []byte) ([]byte, error) {
	reader := hkdf.New(sha256.New, token, salt, []byte(hkdfInfo))
	out := make([]byte, hashSize)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, &TokenHashError{Cause: err}
	}
	return out, nil
}
