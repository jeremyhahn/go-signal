package memory

import (
	"context"
	"sync"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/registration/recoverypassword"
)

// Compile-time interface satisfaction check.
var _ recoverypassword.Store = (*MemoryRecoveryPasswordStore)(nil)

// recoveryPasswordEntry holds a stored hash with its absolute expiration.
type recoveryPasswordEntry struct {
	hash      *recoverypassword.SaltedTokenHash
	expiresAt time.Time
}

// MemoryRecoveryPasswordStore implements recoverypassword.Store with an
// in-memory map. Used by signald in single-node deployments and by every
// non-postgres unit test.
type MemoryRecoveryPasswordStore struct {
	mu      sync.RWMutex
	entries map[string]*recoveryPasswordEntry
	now     func() time.Time
}

// NewMemoryRecoveryPasswordStore creates a new in-memory store.
func NewMemoryRecoveryPasswordStore() *MemoryRecoveryPasswordStore {
	return &MemoryRecoveryPasswordStore{
		entries: make(map[string]*recoveryPasswordEntry),
		now:     time.Now,
	}
}

// SetClock overrides the clock used for expiry checks. Intended for tests.
func (s *MemoryRecoveryPasswordStore) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now != nil {
		s.now = now
	}
}

// Get returns the stored hash for pni or NotFoundError if absent or expired.
// Expired entries are eagerly evicted on read so tests can observe the lazy
// cleanup behavior.
func (s *MemoryRecoveryPasswordStore) Get(_ context.Context, pni string) (*recoverypassword.SaltedTokenHash, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[pni]
	if !ok {
		return nil, &recoverypassword.NotFoundError{PNI: pni}
	}
	if !s.now().Before(entry.expiresAt) {
		delete(s.entries, pni)
		return nil, &recoverypassword.NotFoundError{PNI: pni}
	}
	// Return a copy to prevent caller mutation from leaking back into storage.
	clone := *entry.hash
	return &clone, nil
}

// Put inserts or replaces the entry for pni.
func (s *MemoryRecoveryPasswordStore) Put(_ context.Context, pni string, hash *recoverypassword.SaltedTokenHash, expiresAt time.Time) error {
	if hash == nil {
		return &recoverypassword.InvalidArgumentError{Field: "hash", Message: "must not be nil"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *hash
	s.entries[pni] = &recoveryPasswordEntry{hash: &clone, expiresAt: expiresAt}
	return nil
}

// Delete removes the entry for pni. Idempotent.
func (s *MemoryRecoveryPasswordStore) Delete(_ context.Context, pni string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, pni)
	return nil
}
