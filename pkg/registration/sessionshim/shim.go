package sessionshim

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/extservice/registration"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// DefaultCaptchaEscalationAfter is the CodeRequests threshold at which
// the shim flips a session into captcha-required state. Mirrors the
// Java reference where the second SendCode within a session must clear
// a captcha first.
const DefaultCaptchaEscalationAfter = 1

// Config configures a Shim.
type Config struct {
	// Client is the wire-side surface the shim forwards send/check/
	// create/get calls through. Required.
	Client registration.Client
	// CaptchaStore persists chat-server-side captcha-required flags.
	// Required (use NewMemoryCaptchaStore for the in-process default).
	CaptchaStore CaptchaStore
	// CaptchaChecker validates user-submitted captcha solutions. When
	// nil, SubmitCaptcha returns *verification.CaptchaCheckUnavailableError.
	CaptchaChecker *captcha.Checker
	// CaptchaEscalationAfter controls when SendCode flips the session
	// into captcha-required mode based on the CodeRequests counter the
	// registration-service returns. Zero uses
	// DefaultCaptchaEscalationAfter. A negative value disables
	// escalation entirely.
	CaptchaEscalationAfter int
	// CaptchaScoreThreshold is the minimum upstream captcha score
	// required to accept a submission. Zero uses
	// captcha.DefaultScoreThreshold.
	CaptchaScoreThreshold float64
}

// Shim is the chat-server-side wrapper around a registration.Client
// that adds captcha-required tracking. The REST handler holds a *Shim
// and is unaware of whether the underlying client is in-process or
// gRPC-backed.
type Shim struct {
	client                 registration.Client
	captchaStore           CaptchaStore
	captchaChecker         *captcha.Checker
	captchaEscalationAfter int
	captchaScoreThreshold  float64

	// sendCounts tracks per-session SendCode count chat-server-side.
	// The registration-service proto does not expose CodeRequests, so
	// the shim maintains its own counter to drive captcha escalation
	// decisions. This is intentionally in-memory: a signald restart
	// resets the counter, but the captcha-required flag itself
	// persists in CaptchaStore (which production deployments back
	// with Redis or similar).
	sendCounts sync.Map // map[string]int
}

// NewShim constructs a Shim. Panics if Config.Client or
// Config.CaptchaStore are nil — both are required wiring-time
// invariants.
func NewShim(cfg Config) *Shim {
	if cfg.Client == nil {
		panic("sessionshim: Client is required")
	}
	if cfg.CaptchaStore == nil {
		panic("sessionshim: CaptchaStore is required")
	}
	if cfg.CaptchaEscalationAfter == 0 {
		cfg.CaptchaEscalationAfter = DefaultCaptchaEscalationAfter
	}
	if cfg.CaptchaEscalationAfter < 0 {
		cfg.CaptchaEscalationAfter = 0
	}
	if cfg.CaptchaScoreThreshold == 0 {
		cfg.CaptchaScoreThreshold = captcha.DefaultScoreThreshold
	}
	return &Shim{
		client:                 cfg.Client,
		captchaStore:           cfg.CaptchaStore,
		captchaChecker:         cfg.CaptchaChecker,
		captchaEscalationAfter: cfg.CaptchaEscalationAfter,
		captchaScoreThreshold:  cfg.CaptchaScoreThreshold,
	}
}

// Shutdown closes the underlying client. Always safe to call.
func (s *Shim) Shutdown() {
	_ = s.client.Close()
}

// CreateSession opens a session. The shim clears any stale
// captcha-required flag for the new session ID so a recycled UUID
// cannot inherit prior state.
func (s *Shim) CreateSession(ctx context.Context, number string) (*verification.VerificationSession, error) {
	session, err := s.client.CreateSession(ctx, number)
	if err != nil {
		return nil, err
	}
	_ = s.captchaStore.Clear(ctx, session.ID)
	session.CaptchaRequired = false
	return session, nil
}

// GetSession reads the session from the remote service and merges in
// the locally-tracked captcha-required flag.
func (s *Shim) GetSession(ctx context.Context, sessionID string) (*verification.VerificationSession, error) {
	session, err := s.client.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	required, _ := s.captchaStore.Required(ctx, sessionID)
	session.CaptchaRequired = required
	return session, nil
}

// SendCode blocks if the session is locally flagged as
// captcha-required, otherwise forwards through to the registration
// service. On a successful send, the shim escalates the session into
// captcha-required mode once CodeRequests crosses the threshold.
func (s *Shim) SendCode(ctx context.Context, sessionID string) (*verification.VerificationSession, error) {
	required, err := s.captchaStore.Required(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if required {
		return nil, &verification.CaptchaRequiredError{SessionID: sessionID}
	}
	session, err := s.client.SendCode(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	// Increment the chat-server-side send counter. The proto does not
	// surface CodeRequests, so the shim owns this tally.
	count := s.bumpSendCount(sessionID)
	session.CodeRequests = count
	// Escalation: after the configured number of code requests, mark
	// the session as captcha-required so the NEXT SendCode is gated.
	if s.captchaChecker != nil && s.captchaEscalationAfter > 0 &&
		count >= s.captchaEscalationAfter {
		_ = s.captchaStore.SetRequired(ctx, sessionID, session.ExpiresAt)
		session.CaptchaRequired = true
	}
	return session, nil
}

// bumpSendCount increments and returns the chat-server-side counter
// for SendCode calls against this session.
func (s *Shim) bumpSendCount(sessionID string) int {
	v, _ := s.sendCounts.LoadOrStore(sessionID, 0)
	next := v.(int) + 1
	s.sendCounts.Store(sessionID, next)
	return next
}

// SubmitCode forwards through to the registration service.
func (s *Shim) SubmitCode(ctx context.Context, sessionID, code string) (*verification.VerificationSession, error) {
	return s.client.SubmitCode(ctx, sessionID, code)
}

// SubmitCaptcha verifies the captcha solution locally and, on success,
// clears the captcha-required flag for the session. The session blob
// returned reflects the cleared state so callers can render it
// directly without an extra GetSession round-trip.
func (s *Shim) SubmitCaptcha(ctx context.Context, sessionID, token, remoteIP string) (*verification.VerificationSession, error) {
	if s.captchaChecker == nil {
		return nil, &verification.CaptchaCheckUnavailableError{}
	}
	session, err := s.client.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		return nil, &verification.SessionExpiredError{SessionID: sessionID}
	}
	assess, err := s.captchaChecker.Verify(ctx, captcha.ActionChallenge, token, remoteIP)
	if err != nil {
		// Token-format / provider-lookup / site-key-allowlist errors
		// come back as captcha.* error types; collapse them into a
		// unified *verification.CaptchaRejectedError so the REST
		// handler can map cleanly to 422.
		var (
			parseErr   *captcha.InvalidTokenFormatError
			actionErr  *captcha.InvalidActionError
			provErr    *captcha.UnknownProviderError
			siteKeyErr *captcha.InvalidSiteKeyError
			shortErr   *captcha.ShortCodeUnsupportedError
		)
		switch {
		case errors.As(err, &parseErr),
			errors.As(err, &actionErr),
			errors.As(err, &provErr),
			errors.As(err, &siteKeyErr),
			errors.As(err, &shortErr):
			return nil, &verification.CaptchaRejectedError{SessionID: sessionID, Reason: err.Error()}
		}
		return nil, err
	}
	if !assess.Accepted() {
		return nil, &verification.CaptchaRejectedError{SessionID: sessionID, Reason: "provider rejected solution"}
	}
	if assess.Result.Score > 0 && assess.Result.Score < s.captchaScoreThreshold {
		return nil, &verification.CaptchaRejectedError{SessionID: sessionID, Reason: "score below threshold"}
	}
	_ = s.captchaStore.Clear(ctx, sessionID)
	session.CaptchaRequired = false
	return session, nil
}
