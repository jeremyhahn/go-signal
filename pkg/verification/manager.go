package verification

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultMaxSessions is the default server-wide cap on concurrent verification
// sessions. Unauthenticated callers cannot exceed this limit; once reached,
// CreateSession returns SessionLimitExceededError. Zero means unlimited.
const DefaultMaxSessions = 10_000

// DefaultSessionTTL is the lifetime of a verification session. Sessions older
// than this are treated as expired and cleaned up by the background goroutine.
// This mirrors the Java server's 10-minute TTL for verification sessions.
const DefaultSessionTTL = 10 * time.Minute

// DefaultCleanupInterval is how often the background goroutine sweeps for
// expired sessions.
const DefaultCleanupInterval = 60 * time.Second

// ManagerConfig configures the VerificationManager.
type ManagerConfig struct {
	CodeLength      int           // number of digits in the verification code (default 6)
	CodeTTL         time.Duration // how long a code remains valid (default 5 minutes)
	MaxAttempts     int           // maximum verification attempts per session (default 3)
	MaxSessions     int           // max concurrent sessions; 0 uses DefaultMaxSessions
	SessionTTL      time.Duration // session lifetime; 0 uses DefaultSessionTTL
	CleanupInterval time.Duration // sweep interval; 0 uses DefaultCleanupInterval

	// FixedCode overrides the generated code with a static value when non-empty.
	// This is intended exclusively for integration testing with the stub transport;
	// it must NOT be set in any production configuration.
	FixedCode string
}

// defaultManagerConfig returns a ManagerConfig with production defaults applied
// for any zero-value fields.
func defaultManagerConfig(cfg ManagerConfig) ManagerConfig {
	if cfg.CodeLength <= 0 {
		cfg.CodeLength = 6
	}
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = 5 * time.Minute
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = DefaultMaxSessions
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = DefaultSessionTTL
	}
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = DefaultCleanupInterval
	}
	return cfg
}

// Manager orchestrates verification flows including session creation,
// code generation and delivery, and code submission.
type Manager struct {
	store         VerificationSessionStore
	transport     VerificationTransport
	config        ManagerConfig
	cleanupCancel context.CancelFunc
	shutdownOnce  sync.Once
}

// NewManager creates a new verification Manager with the given store,
// transport, and configuration. Zero-value config fields are replaced with
// production defaults. A background goroutine is started immediately to
// periodically evict expired sessions; call Shutdown to stop it.
func NewManager(store VerificationSessionStore, transport VerificationTransport, config ManagerConfig) *Manager {
	cfg := defaultManagerConfig(config)
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	m := &Manager{
		store:         store,
		transport:     transport,
		config:        cfg,
		cleanupCancel: cleanupCancel,
	}
	go m.runCleanup(cleanupCtx)
	return m
}

// Shutdown stops the background cleanup goroutine. It is safe to call multiple
// times; subsequent calls are no-ops. Callers must always call Shutdown when
// the Manager is no longer needed to avoid goroutine leaks.
func (m *Manager) Shutdown() {
	m.shutdownOnce.Do(func() {
		m.cleanupCancel()
	})
}

// runCleanup periodically calls store.DeleteExpired until ctx is cancelled.
func (m *Manager) runCleanup(ctx context.Context) {
	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Best-effort; errors are not fatal for a cleanup sweep.
			_ = m.store.DeleteExpired(ctx)
		}
	}
}

// CreateSession creates a new verification session for the given phone number.
// It enforces the MaxSessions cap before inserting: if the store already
// holds at least MaxSessions entries, SessionLimitExceededError is returned
// and the caller should surface HTTP 429 to the client.
func (m *Manager) CreateSession(ctx context.Context, number string) (*VerificationSession, error) {
	count, err := m.store.Count(ctx)
	if err != nil {
		return nil, err
	}
	if count >= m.config.MaxSessions {
		return nil, &SessionLimitExceededError{Limit: m.config.MaxSessions}
	}

	now := time.Now()
	session := &VerificationSession{
		ID:                   uuid.New().String(),
		Number:               number,
		AllowedToRequestCode: true,
		CreatedAt:            now,
		ExpiresAt:            now.Add(m.config.SessionTTL),
	}
	if err := m.store.Create(ctx, session); err != nil {
		return nil, err
	}
	return session, nil
}

// SendCode generates a cryptographically random numeric code, stores it in
// the session, and delivers it via the configured transport.
func (m *Manager) SendCode(ctx context.Context, sessionID string) (*VerificationSession, error) {
	session, err := m.store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, &SessionExpiredError{SessionID: sessionID}
	}

	var code string
	if m.config.FixedCode != "" {
		code = m.config.FixedCode
	} else {
		var genErr error
		code, genErr = generateCode(m.config.CodeLength)
		if genErr != nil {
			return nil, genErr
		}
	}

	session.Code = code
	session.ExpiresAt = time.Now().Add(m.config.CodeTTL)
	session.AllowedToRequestCode = false

	if err := m.store.Update(ctx, session); err != nil {
		return nil, err
	}

	if err := m.transport.SendCode(ctx, session.Number, code); err != nil {
		return nil, &TransportError{
			Transport:   m.transport.Name(),
			Destination: session.Number,
			Cause:       err,
		}
	}

	return session, nil
}

// SubmitCode validates the submitted code against the session, enforcing
// maximum attempts and session expiry.
func (m *Manager) SubmitCode(ctx context.Context, sessionID string, code string) (*VerificationSession, error) {
	session, err := m.store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, &SessionExpiredError{SessionID: sessionID}
	}

	if session.Code == "" {
		return nil, &CodeExpiredError{SessionID: sessionID}
	}

	if session.Attempts >= m.config.MaxAttempts {
		return nil, &MaxAttemptsExceededError{
			SessionID:   sessionID,
			MaxAttempts: m.config.MaxAttempts,
		}
	}

	session.Attempts++

	if subtle.ConstantTimeCompare([]byte(session.Code), []byte(code)) != 1 {
		if err := m.store.Update(ctx, session); err != nil {
			return nil, err
		}
		return nil, &InvalidCodeError{SessionID: sessionID}
	}

	session.Verified = true
	session.Code = ""

	if err := m.store.Update(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}

// GetSession retrieves a verification session by ID. It returns
// SessionExpiredError if the session exists but its ExpiresAt is in the past.
func (m *Manager) GetSession(ctx context.Context, sessionID string) (*VerificationSession, error) {
	session, err := m.store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, &SessionExpiredError{SessionID: sessionID}
	}
	return session, nil
}

// generateCode produces a cryptographically random numeric string of the
// specified length using crypto/rand.
func generateCode(length int) (string, error) {
	digits := make([]byte, length)
	for i := range digits {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		digits[i] = byte('0') + byte(n.Int64())
	}
	return string(digits), nil
}
