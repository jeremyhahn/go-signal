package svr2

import (
	"context"
	"errors"
	"sync"
)

// ErrRecordNotFound is returned by Storage.Get when the identity has
// no record. The protocol layer maps this onto Response4.Status MISSING.
var ErrRecordNotFound = errors.New("svr2: record not found")

// Storage persists Records keyed by an identity string (the
// HMAC-derived auth username from chat-server-issued credentials).
// Implementations must be safe for concurrent use.
type Storage interface {
	// Get retrieves the record for identity. Returns ErrRecordNotFound
	// if no record exists.
	Get(ctx context.Context, identity string) (*Record, error)

	// Put writes record. If a previous record existed under the same
	// identity, it is overwritten — Create semantics in SVR4 always
	// replace prior state.
	Put(ctx context.Context, identity string, record *Record) error

	// Delete removes the record for identity. Idempotent: missing
	// keys are not an error.
	Delete(ctx context.Context, identity string) error

	// Count returns the number of stored records. Used by metrics
	// and integration-test assertions.
	Count(ctx context.Context) (int, error)
}

// MemoryStorage is an in-memory Storage implementation. Suitable for
// dev / CI; the production binary points to QrdbStorage.
type MemoryStorage struct {
	mu      sync.RWMutex
	records map[string]*Record
}

// NewMemoryStorage constructs an empty MemoryStorage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{records: make(map[string]*Record)}
}

// Get implements Storage.
func (m *MemoryStorage) Get(_ context.Context, identity string) (*Record, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.records[identity]
	if !ok {
		return nil, ErrRecordNotFound
	}
	return rec.Clone(), nil
}

// Put implements Storage.
func (m *MemoryStorage) Put(_ context.Context, identity string, record *Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[identity] = record.Clone()
	return nil
}

// Delete implements Storage.
func (m *MemoryStorage) Delete(_ context.Context, identity string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, identity)
	return nil
}

// Count implements Storage.
func (m *MemoryStorage) Count(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.records), nil
}
