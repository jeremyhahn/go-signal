package recoverypassword

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// DefaultExpiration is a stored recovery password's lifetime, applied on each Put.
const DefaultExpiration = 30 * 24 * time.Hour // 30 days

// Manager verifies, stores and removes recovery passwords; safe for concurrent use.
type Manager struct {
	store      Store
	expiration time.Duration
	now        func() time.Time
	logger     *slog.Logger
}

// NewManager constructs a Manager that persists to store. expiration controls
// how long stored entries remain valid; pass zero to use DefaultExpiration.
// logger may be nil, in which case slog.Default is used.
func NewManager(store Store, expiration time.Duration, logger *slog.Logger) *Manager {
	if expiration <= 0 {
		expiration = DefaultExpiration
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		store:      store,
		expiration: expiration,
		now:        time.Now,
		logger:     logger,
	}
}

// SetClock overrides the wall-clock used to compute expiration deadlines.
// Intended for tests; production callers should leave the default time.Now in
// place.
func (m *Manager) SetClock(now func() time.Time) {
	if now != nil {
		m.now = now
	}
}

// Verify reports whether password matches pni's unexpired recovery password; errors are store failures only.
func (m *Manager) Verify(ctx context.Context, pni string, password []byte) (bool, error) {
	if pni == "" {
		return false, &InvalidArgumentError{Field: "pni", Message: "must not be empty"}
	}
	if len(password) == 0 {
		return false, &InvalidArgumentError{Field: "password", Message: "must not be empty"}
	}

	stored, err := m.store.Get(ctx, pni)
	if err != nil {
		var nf *NotFoundError
		if errors.As(err, &nf) {
			return false, nil
		}
		m.logger.Warn("failed to lookup registration recovery password",
			slog.String("pni", pni),
			slog.String("error", err.Error()))
		return false, err
	}

	return stored.Verify(TokenFromBytes(password)), nil
}

// Store inserts or replaces the recovery password for pni. The supplied
// password bytes are hashed with a fresh random salt before persisting, so
// concurrent Store calls for the same PNI never produce a hash collision.
func (m *Manager) Store(ctx context.Context, pni string, password []byte) error {
	if pni == "" {
		return &InvalidArgumentError{Field: "pni", Message: "must not be empty"}
	}
	if len(password) == 0 {
		return &InvalidArgumentError{Field: "password", Message: "must not be empty"}
	}

	hash, err := GenerateSaltedTokenHash(TokenFromBytes(password))
	if err != nil {
		return err
	}

	expiresAt := m.now().Add(m.expiration)
	if err := m.store.Put(ctx, pni, hash, expiresAt); err != nil {
		m.logger.Warn("failed to store registration recovery password",
			slog.String("pni", pni),
			slog.String("error", err.Error()))
		return err
	}
	return nil
}

// Remove deletes the recovery password entry for pni. Idempotent: removing a
// non-existent entry returns nil.
func (m *Manager) Remove(ctx context.Context, pni string) error {
	if pni == "" {
		return &InvalidArgumentError{Field: "pni", Message: "must not be empty"}
	}
	if err := m.store.Delete(ctx, pni); err != nil {
		m.logger.Warn("failed to remove registration recovery password",
			slog.String("pni", pni),
			slog.String("error", err.Error()))
		return err
	}
	return nil
}
