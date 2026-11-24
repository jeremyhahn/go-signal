package secrets

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
)

// autoGenSentinels are the values that trigger automatic secret generation.
var autoGenSentinels = map[string]struct{}{
	"auto":        {},
	"changeme":    {},
	"placeholder": {},
}

// AutoGenResolver generates cryptographically random secrets for sentinel
// values ("auto", "changeme", "placeholder"). Once a secret is generated for
// a given sentinel, the same SecureString value is returned on subsequent
// calls (cached in memory for the lifetime of the resolver). Cached entries
// are SecureStrings stored in the enclave so the plaintext is not held in
// ordinary heap memory between calls.
type AutoGenResolver struct {
	byteLength int
	mu         sync.RWMutex
	cache      map[string]*SecureString
}

// NewAutoGenResolver creates an AutoGenResolver that generates secrets of
// the given byte length (encoded as hex, so the resulting string is 2x
// byteLength characters).
func NewAutoGenResolver(byteLength int) *AutoGenResolver {
	if byteLength <= 0 {
		byteLength = 32
	}
	return &AutoGenResolver{
		byteLength: byteLength,
		cache:      make(map[string]*SecureString),
	}
}

// Scheme returns "autogen". This resolver is special — it is checked for
// sentinel values rather than URI schemes.
func (r *AutoGenResolver) Scheme() string {
	return "autogen"
}

// Resolve generates a random hex-encoded secret for recognized sentinel
// values, wrapped in a SecureString. Non-sentinel values are wrapped
// unchanged. Generated values are cached by the input sentinel key so
// repeated calls return the same secret.
func (r *AutoGenResolver) Resolve(_ context.Context, value string) (*SecureString, error) {
	if !IsSentinel(value) {
		return NewOptionalSecureString(value)
	}

	r.mu.RLock()
	if cached, ok := r.cache[value]; ok {
		r.mu.RUnlock()
		// Return a fresh SecureString with the same plaintext so each caller
		// holds independent ownership and can call Destroy independently.
		plain := cached.Plaintext()
		return NewSecureString(plain)
	}
	r.mu.RUnlock()

	secret, err := generateRandomHex(r.byteLength)
	if err != nil {
		return nil, err
	}

	// Seal both copies before taking the write lock so a sealing failure
	// aborts the resolution instead of leaving an unset entry in the cache.
	entry, err := NewSecureString(secret)
	if err != nil {
		return nil, err
	}
	// Wipe the intermediate hex string from stack memory as much as Go allows.
	secretCopy, err := NewSecureString(secret)
	if err != nil {
		entry.Destroy()
		return nil, err
	}

	r.mu.Lock()
	// Double-check after acquiring write lock.
	if cached, ok := r.cache[value]; ok {
		r.mu.Unlock()
		plain := cached.Plaintext()
		entry.Destroy()
		secretCopy.Destroy()
		return NewSecureString(plain)
	}
	r.cache[value] = entry
	r.mu.Unlock()

	return secretCopy, nil
}

// IsSentinel reports whether the given value is an auto-generation sentinel.
func IsSentinel(value string) bool {
	_, ok := autoGenSentinels[value]
	return ok
}

// generateRandomHex generates n random bytes and returns their hex encoding.
func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
