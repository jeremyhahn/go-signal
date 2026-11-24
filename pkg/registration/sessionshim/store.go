// Package sessionshim wraps a remote registration-service with signald's captcha gate, blocking SendCode until a required captcha is cleared.
package sessionshim

import (
	"context"
	"sync"
	"time"
)

// CaptchaStore persists the chat-server-side captcha-required flag per
// session. Implementations must be safe for concurrent use.
type CaptchaStore interface {
	// SetRequired marks the session as needing a captcha solution
	// before the next SendCode call. expiresAt bounds the entry so the
	// store can sweep stale flags when the session itself expires.
	SetRequired(ctx context.Context, sessionID string, expiresAt time.Time) error
	// Clear removes the captcha-required flag. Idempotent.
	Clear(ctx context.Context, sessionID string) error
	// Required reports whether the session currently needs a captcha.
	Required(ctx context.Context, sessionID string) (bool, error)
}

// MemoryCaptchaStore is the in-memory CaptchaStore implementation. A
// background goroutine sweeps expired entries on a fixed cadence.
type MemoryCaptchaStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// NewMemoryCaptchaStore returns an empty in-memory CaptchaStore.
func NewMemoryCaptchaStore() *MemoryCaptchaStore {
	return &MemoryCaptchaStore{entries: make(map[string]time.Time)}
}

// SetRequired marks the given session as needing a captcha until
// expiresAt.
func (m *MemoryCaptchaStore) SetRequired(_ context.Context, sessionID string, expiresAt time.Time) error {
	m.mu.Lock()
	m.entries[sessionID] = expiresAt
	m.mu.Unlock()
	return nil
}

// Clear removes the captcha-required mark for sessionID.
func (m *MemoryCaptchaStore) Clear(_ context.Context, sessionID string) error {
	m.mu.Lock()
	delete(m.entries, sessionID)
	m.mu.Unlock()
	return nil
}

// Required reports whether sessionID currently needs a captcha,
// auto-pruning the entry when its expiresAt is in the past.
func (m *MemoryCaptchaStore) Required(_ context.Context, sessionID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	expiresAt, ok := m.entries[sessionID]
	if !ok {
		return false, nil
	}
	if time.Now().After(expiresAt) {
		delete(m.entries, sessionID)
		return false, nil
	}
	return true, nil
}

// Sweep removes expired captcha-required entries. Callers may invoke
// this on a background ticker.
func (m *MemoryCaptchaStore) Sweep() {
	now := time.Now()
	m.mu.Lock()
	for k, v := range m.entries {
		if now.After(v) {
			delete(m.entries, k)
		}
	}
	m.mu.Unlock()
}
