package verification

import (
	"context"
	"sync"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// MemoryVerificationSessionStore is a thread-safe in-memory implementation
// of VerificationSessionStore. It deep-copies sessions on retrieval to
// prevent external mutation of internal state.
type MemoryVerificationSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*VerificationSession
}

// NewMemoryVerificationSessionStore returns a new in-memory session store.
func NewMemoryVerificationSessionStore() *MemoryVerificationSessionStore {
	return &MemoryVerificationSessionStore{
		sessions: make(map[string]*VerificationSession),
	}
}

// Create stores a new verification session. Returns an error if a session
// already exists with the same ID, matching qrdb and postgres semantics.
func (s *MemoryVerificationSessionStore) Create(_ context.Context, session *VerificationSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[session.ID]; exists {
		return signalerrors.New(signalerrors.ErrAlreadyExists, "memory verification: session already exists: "+session.ID)
	}
	s.sessions[session.ID] = copySession(session)
	return nil
}

// Get retrieves a verification session by ID. Returns a deep copy to prevent
// callers from mutating internal state.
func (s *MemoryVerificationSessionStore) Get(_ context.Context, sessionID string) (*VerificationSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, &SessionNotFoundError{SessionID: sessionID}
	}
	return copySession(session), nil
}

// Update replaces an existing verification session.
func (s *MemoryVerificationSessionStore) Update(_ context.Context, session *VerificationSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[session.ID]; !ok {
		return &SessionNotFoundError{SessionID: session.ID}
	}
	s.sessions[session.ID] = copySession(session)
	return nil
}

// Delete removes a verification session by ID.
func (s *MemoryVerificationSessionStore) Delete(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sessionID]; !ok {
		return &SessionNotFoundError{SessionID: sessionID}
	}
	delete(s.sessions, sessionID)
	return nil
}

// Count returns the number of sessions currently in the store.
func (s *MemoryVerificationSessionStore) Count(_ context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions), nil
}

// DeleteExpired removes all sessions whose ExpiresAt is in the past.
func (s *MemoryVerificationSessionStore) DeleteExpired(_ context.Context) error {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	return nil
}

// copySession returns a deep copy of the given VerificationSession.
func copySession(src *VerificationSession) *VerificationSession {
	cp := *src
	return &cp
}
