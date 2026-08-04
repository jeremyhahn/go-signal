package captcha

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

const (
	// DefaultScoreThreshold is the minimum acceptable reCAPTCHA v3 score.
	// For services that do not emit a score the check is skipped (score == 0).
	DefaultScoreThreshold = 0.5
)

// challengeHandlers maps each ChallengeType to its verification function,
// following the project convention of map-based dispatch over switch statements.
var challengeHandlers = map[ChallengeType]func(m *CaptchaManager, ctx context.Context, accountUUID string, resp *ChallengeResponse) error{
	ChallengeTypeCaptcha: (*CaptchaManager).handleCaptchaChallenge,
	ChallengeTypePush:    (*CaptchaManager).handlePushChallenge,
}

// CaptchaManager coordinates challenge issuance and verification for rate
// limit mitigation and abuse prevention.
type CaptchaManager struct {
	verifier       CaptchaVerifier
	checker        *Checker
	scoreThreshold float64
	logger         *slog.Logger
}

// CaptchaManagerConfig holds the parameters for constructing a CaptchaManager.
type CaptchaManagerConfig struct {
	// Verifier is the legacy single-provider backend used when no Checker
	// is configured. Required when Checker is nil; ignored otherwise.
	Verifier CaptchaVerifier

	// Checker is the token-format-aware multi-provider dispatcher
	// (Phase 3.3). When non-nil, handleCaptchaChallenge parses the
	// captcha solution as `provider.sitekey.action.token`, enforces the
	// per-action site-key allowlist, and delegates to the resolved
	// provider. Leave nil to retain the legacy single-verifier flow.
	Checker *Checker

	// ScoreThreshold is the minimum VerifyResult.Score required to accept a
	// token. Scores are only emitted by reCAPTCHA v3; for other providers the
	// returned score is 0 and the threshold check is skipped. A zero value
	// uses DefaultScoreThreshold.
	ScoreThreshold float64

	// Logger is used for debug and error output. Required.
	Logger *slog.Logger
}

// NewCaptchaManager creates a new CaptchaManager with the given logger.
// The manager uses a TestVerifier that accepts any token carrying the
// TestTokenPrefix. Use NewCaptchaManagerWithConfig to supply a production
// CAPTCHA backend.
func NewCaptchaManager(logger *slog.Logger) *CaptchaManager {
	return NewCaptchaManagerWithConfig(CaptchaManagerConfig{
		Verifier:       NewTestVerifier(TestVerifierConfig{}),
		ScoreThreshold: DefaultScoreThreshold,
		Logger:         logger,
	})
}

// NewCaptchaManagerWithConfig creates a CaptchaManager configured with the
// provided options. ScoreThreshold defaults to DefaultScoreThreshold when
// zero.
func NewCaptchaManagerWithConfig(cfg CaptchaManagerConfig) *CaptchaManager {
	threshold := cfg.ScoreThreshold
	if threshold == 0 {
		threshold = DefaultScoreThreshold
	}
	return &CaptchaManager{
		verifier:       cfg.Verifier,
		checker:        cfg.Checker,
		scoreThreshold: threshold,
		logger:         cfg.Logger,
	}
}

// HandleChallengeResponse verifies a challenge response submitted by a client.
// The response type determines which verification path is invoked via
// map-based dispatch.
func (m *CaptchaManager) HandleChallengeResponse(ctx context.Context, accountUUID string, resp *ChallengeResponse) error {
	handler, ok := challengeHandlers[resp.Type]
	if !ok {
		return &InvalidChallengeTypeError{Type: string(resp.Type)}
	}
	return handler(m, ctx, accountUUID, resp)
}

// SendPushChallenge generates a new push challenge token for the specified
// account. The token is a UUID that the client must return via a challenge
// response after receiving it through a push notification.
func (m *CaptchaManager) SendPushChallenge(ctx context.Context, accountUUID string) (string, error) {
	token := uuid.New().String()

	m.logger.DebugContext(ctx, "issued push challenge",
		slog.String("uuid", accountUUID),
		slog.String("token", token),
	)

	return token, nil
}

// handleCaptchaChallenge verifies a CAPTCHA challenge response by delegating
// to the configured CaptchaVerifier. Both the challenge token (the push-round-
// trip token) and the captcha solution (the CAPTCHA widget response) must be
// present. The captcha solution is forwarded to the verifier; if the upstream
// service rejects it, or if the score falls below the threshold, the challenge
// fails.
func (m *CaptchaManager) handleCaptchaChallenge(ctx context.Context, accountUUID string, resp *ChallengeResponse) error {
	if resp.Token == "" {
		return &ChallengeFailedError{Message: "missing token"}
	}
	if resp.Captcha == "" {
		return &ChallengeFailedError{Message: "missing captcha solution"}
	}

	var (
		result *VerifyResult
		err    error
	)
	if m.checker != nil {
		// Multi-provider path: parse the dotted token format and enforce
		// the ActionChallenge tag + site-key allowlist before delegating
		// to the resolved provider.
		var assess *Assessment
		assess, err = m.checker.Verify(ctx, ActionChallenge, resp.Captcha, "")
		if err == nil {
			result = assess.Result
		}
	} else {
		result, err = m.verifier.Verify(ctx, resp.Captcha, "", "")
	}
	if err != nil {
		m.logger.ErrorContext(ctx, "captcha verifier error",
			slog.String("uuid", accountUUID),
			slog.String("error", err.Error()),
		)
		return err
	}

	if !result.Success {
		m.logger.WarnContext(ctx, "captcha verification rejected",
			slog.String("uuid", accountUUID),
			slog.Any("error_codes", result.ErrorCodes),
		)
		return &CaptchaVerificationFailedError{ErrorCodes: result.ErrorCodes}
	}

	// Score > 0 means the provider returned a score (reCAPTCHA v3).
	// Apply the threshold only when a score was actually emitted.
	if result.Score > 0 && result.Score < m.scoreThreshold {
		m.logger.WarnContext(ctx, "captcha score below threshold",
			slog.String("uuid", accountUUID),
			slog.Float64("score", result.Score),
			slog.Float64("threshold", m.scoreThreshold),
		)
		return &CaptchaVerificationFailedError{}
	}

	m.logger.DebugContext(ctx, "captcha challenge accepted",
		slog.String("uuid", accountUUID),
	)

	return nil
}

// handlePushChallenge verifies a push-based rate limit challenge response.
// In production this validates the token against a previously issued challenge;
// the current implementation validates that the required fields are present.
func (m *CaptchaManager) handlePushChallenge(ctx context.Context, accountUUID string, resp *ChallengeResponse) error {
	if resp.Token == "" {
		return &ChallengeFailedError{Message: "missing token"}
	}

	m.logger.DebugContext(ctx, "push challenge accepted",
		slog.String("uuid", accountUUID),
	)

	return nil
}
