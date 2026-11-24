// Package core is the registration-service engine: sessions, code generation, per-session rate limits and transport delivery. Captcha is handled by pkg/registration/sessionshim.
package core

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// DefaultMaxSessions caps concurrent sessions (then *verification.SessionLimitExceededError); zero uses it, negative disables the cap.
const DefaultMaxSessions = 10_000

// DefaultSessionTTL is the session lifetime — 10 minutes, matching the
// Java reference. The background sweep evicts older sessions.
const DefaultSessionTTL = 10 * time.Minute

// DefaultCleanupInterval is how often the background goroutine sweeps
// the session store for expired entries.
const DefaultCleanupInterval = 60 * time.Second

// DefaultRequestCodeCooldowns is the per-session cooldown schedule: immediate, then 60s, 5m, 30m, capped at 1h.
var DefaultRequestCodeCooldowns = []time.Duration{
	0,
	60 * time.Second,
	5 * time.Minute,
	30 * time.Minute,
	60 * time.Minute,
}

// Config configures Service. Zero-value fields are replaced with
// production defaults at construction time.
type Config struct {
	CodeLength      int
	CodeTTL         time.Duration
	MaxAttempts     int
	MaxSessions     int
	SessionTTL      time.Duration
	CleanupInterval time.Duration
	// RequestCodeCooldowns is indexed by CodeRequests and clamps to its last value; empty disables per-session limits.
	RequestCodeCooldowns []time.Duration
	// FixedCode replaces the random code with a static value. Intended
	// exclusively for integration testing against the stub transport;
	// production configuration must leave this empty.
	FixedCode string
}

func defaultConfig(cfg Config) Config {
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
	if cfg.RequestCodeCooldowns == nil {
		cfg.RequestCodeCooldowns = DefaultRequestCodeCooldowns
	}
	return cfg
}

// Service is the verification-side state engine. A single Service
// instance is shared by all RPCs of the registration-service binary.
type Service struct {
	store         verification.VerificationSessionStore
	transport     verification.VerificationTransport
	config        Config
	cleanupCancel context.CancelFunc
	shutdownOnce  sync.Once
}

// NewService returns a Service and starts its cleanup goroutine; call Shutdown when done.
func NewService(store verification.VerificationSessionStore, transport verification.VerificationTransport, config Config) *Service {
	cfg := defaultConfig(config)
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	s := &Service{
		store:         store,
		transport:     transport,
		config:        cfg,
		cleanupCancel: cleanupCancel,
	}
	go s.runCleanup(cleanupCtx)
	return s
}

// Shutdown stops the background cleanup goroutine. Safe to call
// multiple times; subsequent calls are no-ops.
func (s *Service) Shutdown() {
	s.shutdownOnce.Do(func() {
		s.cleanupCancel()
	})
}

func (s *Service) runCleanup(ctx context.Context) {
	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.store.DeleteExpired(ctx)
		}
	}
}

// CreateSession opens a new verification session for the supplied E.164
// number. Returns *verification.SessionLimitExceededError when the
// store already holds MaxSessions entries.
func (s *Service) CreateSession(ctx context.Context, number string) (*verification.VerificationSession, error) {
	count, err := s.store.Count(ctx)
	if err != nil {
		return nil, err
	}
	if count >= s.config.MaxSessions {
		return nil, &verification.SessionLimitExceededError{Limit: s.config.MaxSessions}
	}
	now := time.Now()
	session := &verification.VerificationSession{
		ID:                   uuid.New().String(),
		Number:               number,
		AllowedToRequestCode: true,
		CreatedAt:            now,
		ExpiresAt:            now.Add(s.config.SessionTTL),
	}
	if err := s.store.Create(ctx, session); err != nil {
		return nil, err
	}
	return session, nil
}

// SendCode generates, stores and sends a code; within the cooldown it returns *verification.RequestCodeRateLimitedError with the remaining wait.
func (s *Service) SendCode(ctx context.Context, sessionID string) (*verification.VerificationSession, error) {
	session, err := s.store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if now.After(session.ExpiresAt) {
		return nil, &verification.SessionExpiredError{SessionID: sessionID}
	}
	// The verified check precedes the cooldown, so a recently verified session is not told to wait.
	if session.Verified {
		return nil, &verification.SessionAlreadyVerifiedError{SessionID: sessionID}
	}
	if !session.NextCodeRequestAt.IsZero() && now.Before(session.NextCodeRequestAt) {
		return nil, &verification.RequestCodeRateLimitedError{
			SessionID:  sessionID,
			RetryAfter: session.NextCodeRequestAt.Sub(now),
		}
	}

	var code string
	if s.config.FixedCode != "" {
		code = s.config.FixedCode
	} else {
		generated, genErr := generateCode(s.config.CodeLength)
		if genErr != nil {
			return nil, genErr
		}
		code = generated
	}

	session.Code = code
	session.ExpiresAt = now.Add(s.config.CodeTTL)
	session.AllowedToRequestCode = false
	session.CodeRequests++
	session.NextCodeRequestAt = now.Add(s.nextCooldown(session.CodeRequests))

	if err := s.store.Update(ctx, session); err != nil {
		return nil, err
	}
	if err := s.transport.SendCode(ctx, session.Number, code); err != nil {
		return nil, &verification.TransportError{
			Transport:   s.transport.Name(),
			Destination: session.Number,
			Cause:       err,
		}
	}
	return session, nil
}

// SubmitCode compares codes in constant time; a mismatch is *verification.InvalidCodeError, and past MaxAttempts *MaxAttemptsExceededError.
func (s *Service) SubmitCode(ctx context.Context, sessionID, code string) (*verification.VerificationSession, error) {
	session, err := s.store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, &verification.SessionExpiredError{SessionID: sessionID}
	}
	if session.Code == "" {
		return nil, &verification.CodeExpiredError{SessionID: sessionID}
	}
	if session.Attempts >= s.config.MaxAttempts {
		return nil, &verification.MaxAttemptsExceededError{
			SessionID:   sessionID,
			MaxAttempts: s.config.MaxAttempts,
		}
	}
	session.Attempts++
	if subtle.ConstantTimeCompare([]byte(session.Code), []byte(code)) != 1 {
		if err := s.store.Update(ctx, session); err != nil {
			return nil, err
		}
		return nil, &verification.InvalidCodeError{SessionID: sessionID}
	}
	session.Verified = true
	session.Code = ""
	if err := s.store.Update(ctx, session); err != nil {
		return nil, err
	}
	return session, nil
}

// GetSession retrieves a session by ID. Returns
// *verification.SessionExpiredError when the session exists but its
// ExpiresAt is in the past.
func (s *Service) GetSession(ctx context.Context, sessionID string) (*verification.VerificationSession, error) {
	session, err := s.store.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, &verification.SessionExpiredError{SessionID: sessionID}
	}
	return session, nil
}

func (s *Service) nextCooldown(requests int) time.Duration {
	sched := s.config.RequestCodeCooldowns
	if len(sched) == 0 {
		return 0
	}
	idx := requests
	if idx >= len(sched) {
		idx = len(sched) - 1
	}
	return sched[idx]
}

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
