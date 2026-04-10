package memory

import (
	"context"
	"sync"

	"github.com/jeremyhahn/go-signal/pkg/devices"
)

// Compile-time interface satisfaction check.
var _ devices.ProvisioningStore = (*MemoryProvisioningStore)(nil)

// MemoryProvisioningStore implements devices.ProvisioningStore with an
// in-memory map. It is safe for concurrent use.
type MemoryProvisioningStore struct {
	mu       sync.RWMutex
	sessions map[string]*devices.ProvisioningSession
}

// NewMemoryProvisioningStore creates a new in-memory provisioning store.
func NewMemoryProvisioningStore() *MemoryProvisioningStore {
	return &MemoryProvisioningStore{
		sessions: make(map[string]*devices.ProvisioningSession),
	}
}

// StoreSession persists a provisioning session keyed by its verification code.
// The session is deep-copied to prevent mutations through the caller's pointer
// from affecting stored state.
func (s *MemoryProvisioningStore) StoreSession(_ context.Context, session *devices.ProvisioningSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.Code] = cloneSession(session)
	return nil
}

// GetSession retrieves a provisioning session by its verification code. Returns
// an InvalidProvisioningCodeError if the code does not exist. The returned
// session is a deep copy; callers may mutate it without affecting stored state.
func (s *MemoryProvisioningStore) GetSession(_ context.Context, code string) (*devices.ProvisioningSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[code]
	if !exists {
		return nil, &devices.InvalidProvisioningCodeError{Code: code}
	}

	return cloneSession(session), nil
}

// cloneSession returns a deep copy of a ProvisioningSession. All fields are
// value types (string, time.Time) so a struct copy is sufficient.
func cloneSession(s *devices.ProvisioningSession) *devices.ProvisioningSession {
	clone := *s
	return &clone
}

// DeleteSession removes a provisioning session by its verification code. This
// operation is idempotent.
func (s *MemoryProvisioningStore) DeleteSession(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, code)
	return nil
}
