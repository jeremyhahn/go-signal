package captcha

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, nil))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// newTestManager returns a CaptchaManager configured with a TestVerifier that
// accepts any token carrying the TestTokenPrefix. All existing tests that
// previously passed arbitrary strings are updated to use a valid test token.
func newTestManager() *CaptchaManager {
	return NewCaptchaManagerWithConfig(CaptchaManagerConfig{
		Verifier:       NewTestVerifier(TestVerifierConfig{}),
		ScoreThreshold: DefaultScoreThreshold,
		Logger:         testLogger(),
	})
}

func TestNewCaptchaManager_NotNil(t *testing.T) {
	m := NewCaptchaManager(testLogger())
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewCaptchaManager_StoresLogger(t *testing.T) {
	logger := testLogger()
	m := NewCaptchaManager(logger)
	if m.logger != logger {
		t.Error("logger not stored correctly")
	}
}

func TestHandleChallengeResponse_CaptchaSuccess(t *testing.T) {
	m := newTestManager()
	resp := &ChallengeResponse{
		Type:    ChallengeTypeCaptcha,
		Token:   "tok-123",
		Captcha: TestTokenPrefix + "valid",
	}
	err := m.HandleChallengeResponse(context.Background(), "uuid-1", resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleChallengeResponse_CaptchaMissingToken(t *testing.T) {
	m := newTestManager()
	resp := &ChallengeResponse{
		Type:    ChallengeTypeCaptcha,
		Token:   "",
		Captcha: TestTokenPrefix + "valid",
	}
	err := m.HandleChallengeResponse(context.Background(), "uuid-1", resp)
	if err == nil {
		t.Fatal("expected error for missing token")
	}
	var target *ChallengeFailedError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ChallengeFailedError, got %T", err)
	}
	if target.Message != "missing token" {
		t.Errorf("got message %q, want %q", target.Message, "missing token")
	}
}

func TestHandleChallengeResponse_CaptchaMissingSolution(t *testing.T) {
	m := newTestManager()
	resp := &ChallengeResponse{
		Type:    ChallengeTypeCaptcha,
		Token:   "tok-123",
		Captcha: "",
	}
	err := m.HandleChallengeResponse(context.Background(), "uuid-1", resp)
	if err == nil {
		t.Fatal("expected error for missing captcha solution")
	}
	var target *ChallengeFailedError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ChallengeFailedError, got %T", err)
	}
	if target.Message != "missing captcha solution" {
		t.Errorf("got message %q, want %q", target.Message, "missing captcha solution")
	}
}

func TestHandleChallengeResponse_PushSuccess(t *testing.T) {
	m := newTestManager()
	resp := &ChallengeResponse{
		Type:  ChallengeTypePush,
		Token: "push-tok-456",
	}
	err := m.HandleChallengeResponse(context.Background(), "uuid-2", resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleChallengeResponse_PushMissingToken(t *testing.T) {
	m := newTestManager()
	resp := &ChallengeResponse{
		Type:  ChallengeTypePush,
		Token: "",
	}
	err := m.HandleChallengeResponse(context.Background(), "uuid-2", resp)
	if err == nil {
		t.Fatal("expected error for missing push token")
	}
	var target *ChallengeFailedError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ChallengeFailedError, got %T", err)
	}
	if target.Message != "missing token" {
		t.Errorf("got message %q, want %q", target.Message, "missing token")
	}
}

func TestHandleChallengeResponse_InvalidType(t *testing.T) {
	m := newTestManager()
	resp := &ChallengeResponse{
		Type:  ChallengeType("bogus"),
		Token: "tok",
	}
	err := m.HandleChallengeResponse(context.Background(), "uuid-3", resp)
	if err == nil {
		t.Fatal("expected error for invalid challenge type")
	}
	var target *InvalidChallengeTypeError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidChallengeTypeError, got %T", err)
	}
	if target.Type != "bogus" {
		t.Errorf("got type %q, want %q", target.Type, "bogus")
	}
}

func TestHandleChallengeResponse_EmptyType(t *testing.T) {
	m := newTestManager()
	resp := &ChallengeResponse{
		Type:  ChallengeType(""),
		Token: "tok",
	}
	err := m.HandleChallengeResponse(context.Background(), "uuid-3", resp)
	if err == nil {
		t.Fatal("expected error for empty challenge type")
	}
	var target *InvalidChallengeTypeError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidChallengeTypeError, got %T", err)
	}
}

func TestSendPushChallenge_ReturnsToken(t *testing.T) {
	m := newTestManager()
	token, err := m.SendPushChallenge(context.Background(), "uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestSendPushChallenge_UniqueTokens(t *testing.T) {
	m := newTestManager()
	token1, err := m.SendPushChallenge(context.Background(), "uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	token2, err := m.SendPushChallenge(context.Background(), "uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token1 == token2 {
		t.Error("expected unique tokens for each call")
	}
}

func TestSendPushChallenge_WithCancelledContext(t *testing.T) {
	m := newTestManager()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	token, err := m.SendPushChallenge(ctx, "uuid-1")
	// The current implementation does not check context, so should still succeed
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestHandleCaptchaChallenge_BothFieldsPresent(t *testing.T) {
	m := newTestManager()
	err := m.handleCaptchaChallenge(context.Background(), "uuid-1", &ChallengeResponse{
		Token:   "tok",
		Captcha: TestTokenPrefix + "sol",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleCaptchaChallenge_EmptyBoth(t *testing.T) {
	m := newTestManager()
	err := m.handleCaptchaChallenge(context.Background(), "uuid-1", &ChallengeResponse{})
	if err == nil {
		t.Fatal("expected error")
	}
	var target *ChallengeFailedError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ChallengeFailedError, got %T", err)
	}
	// Token is checked first
	if target.Message != "missing token" {
		t.Errorf("got %q, want %q", target.Message, "missing token")
	}
}

func TestHandlePushChallenge_ValidToken(t *testing.T) {
	m := newTestManager()
	err := m.handlePushChallenge(context.Background(), "uuid-1", &ChallengeResponse{
		Token: "push-tok",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandlePushChallenge_EmptyToken(t *testing.T) {
	m := newTestManager()
	err := m.handlePushChallenge(context.Background(), "uuid-1", &ChallengeResponse{})
	if err == nil {
		t.Fatal("expected error")
	}
	var target *ChallengeFailedError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ChallengeFailedError, got %T", err)
	}
}

func TestChallengeHandlers_MapContainsExpectedKeys(t *testing.T) {
	expectedTypes := []ChallengeType{ChallengeTypeCaptcha, ChallengeTypePush}
	for _, ct := range expectedTypes {
		if _, ok := challengeHandlers[ct]; !ok {
			t.Errorf("challengeHandlers missing key %q", ct)
		}
	}
}

func TestChallengeHandlers_MapSize(t *testing.T) {
	if got := len(challengeHandlers); got != 2 {
		t.Errorf("expected 2 handlers, got %d", got)
	}
}

// --------------------------------------------------------------------------
// NewCaptchaManagerWithConfig
// --------------------------------------------------------------------------

func TestNewCaptchaManagerWithConfig_CustomVerifier(t *testing.T) {
	v := NewTestVerifier(TestVerifierConfig{ValidTokens: []string{"explicit-token"}})
	m := NewCaptchaManagerWithConfig(CaptchaManagerConfig{
		Verifier:       v,
		ScoreThreshold: 0.7,
		Logger:         testLogger(),
	})
	if m == nil {
		t.Fatal("expected non-nil manager")
		return
	}
	if m.scoreThreshold != 0.7 {
		t.Errorf("got threshold %v, want 0.7", m.scoreThreshold)
	}
}

func TestNewCaptchaManagerWithConfig_ZeroThresholdUsesDefault(t *testing.T) {
	m := NewCaptchaManagerWithConfig(CaptchaManagerConfig{
		Verifier: NewTestVerifier(TestVerifierConfig{}),
		Logger:   testLogger(),
		// ScoreThreshold is zero — should default.
	})
	if m.scoreThreshold != DefaultScoreThreshold {
		t.Errorf("got threshold %v, want %v", m.scoreThreshold, DefaultScoreThreshold)
	}
}

// --------------------------------------------------------------------------
// CaptchaManager with verifier returning failure
// --------------------------------------------------------------------------

func TestHandleCaptchaChallenge_VerifierRejectsToken(t *testing.T) {
	m := newTestManager()
	// "bad-token" does not carry TestTokenPrefix and is not in the allow-set.
	err := m.handleCaptchaChallenge(context.Background(), "uuid-1", &ChallengeResponse{
		Token:   "tok",
		Captcha: "bad-token",
	})
	if err == nil {
		t.Fatal("expected error for rejected captcha token")
	}
	var target *CaptchaVerificationFailedError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CaptchaVerificationFailedError, got %T", err)
	}
}

func TestHandleCaptchaChallenge_VerifierErrorPropagates(t *testing.T) {
	// Use an errVerifier that always returns an error to cover the error path.
	m := NewCaptchaManagerWithConfig(CaptchaManagerConfig{
		Verifier: &errVerifier{err: &CaptchaNetworkError{Provider: "test", Cause: errors.New("dial failed")}},
		Logger:   testLogger(),
	})
	err := m.handleCaptchaChallenge(context.Background(), "uuid-1", &ChallengeResponse{
		Token:   "tok",
		Captcha: TestTokenPrefix + "ok",
	})
	if err == nil {
		t.Fatal("expected error to propagate from verifier")
	}
	var target *CaptchaNetworkError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CaptchaNetworkError, got %T", err)
	}
}

// --------------------------------------------------------------------------
// Score threshold enforcement
// --------------------------------------------------------------------------

func TestHandleCaptchaChallenge_LowScoreRejected(t *testing.T) {
	// scoreVerifier returns score 0.3 — below the 0.5 default threshold.
	m := NewCaptchaManagerWithConfig(CaptchaManagerConfig{
		Verifier:       &scoreVerifier{score: 0.3},
		ScoreThreshold: DefaultScoreThreshold,
		Logger:         testLogger(),
	})
	err := m.handleCaptchaChallenge(context.Background(), "uuid-1", &ChallengeResponse{
		Token:   "tok",
		Captcha: "any",
	})
	if err == nil {
		t.Fatal("expected error for low score")
	}
	var target *CaptchaVerificationFailedError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CaptchaVerificationFailedError, got %T", err)
	}
}

func TestHandleCaptchaChallenge_AboveThresholdAccepted(t *testing.T) {
	// scoreVerifier returns score 0.8 — above the 0.5 default threshold.
	m := NewCaptchaManagerWithConfig(CaptchaManagerConfig{
		Verifier:       &scoreVerifier{score: 0.8},
		ScoreThreshold: DefaultScoreThreshold,
		Logger:         testLogger(),
	})
	err := m.handleCaptchaChallenge(context.Background(), "uuid-1", &ChallengeResponse{
		Token:   "tok",
		Captcha: "any",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleCaptchaChallenge_ZeroScoreSkipsThreshold(t *testing.T) {
	// A zero score (hCaptcha / v2) must not be treated as "below threshold".
	m := NewCaptchaManagerWithConfig(CaptchaManagerConfig{
		Verifier:       &scoreVerifier{score: 0},
		ScoreThreshold: DefaultScoreThreshold,
		Logger:         testLogger(),
	})
	err := m.handleCaptchaChallenge(context.Background(), "uuid-1", &ChallengeResponse{
		Token:   "tok",
		Captcha: "any",
	})
	if err != nil {
		t.Fatalf("unexpected error for zero-score provider: %v", err)
	}
}

// --------------------------------------------------------------------------
// Test helpers: stub verifiers
// --------------------------------------------------------------------------

// errVerifier always returns the configured error.
type errVerifier struct{ err error }

func (v *errVerifier) Verify(_ context.Context, _, _, _ string) (*VerifyResult, error) {
	return nil, v.err
}

// scoreVerifier returns a successful result with a configurable score.
type scoreVerifier struct{ score float64 }

func (v *scoreVerifier) Verify(_ context.Context, _, _, _ string) (*VerifyResult, error) {
	return &VerifyResult{Success: true, Score: v.score}, nil
}

// --------------------------------------------------------------------------
// No provider configured
// --------------------------------------------------------------------------

// newUnconfiguredManager mirrors what cmd/signald builds when the deployment
// names no captcha provider: buildCaptchaChecker yields no Checker, and the
// config supplies no Verifier either.
func newUnconfiguredManager() *CaptchaManager {
	return NewCaptchaManagerWithConfig(CaptchaManagerConfig{Logger: testLogger()})
}

func TestHandleChallengeResponse_CaptchaNoProviderConfigured(t *testing.T) {
	m := newUnconfiguredManager()
	resp := &ChallengeResponse{
		Type:    ChallengeTypeCaptcha,
		Token:   "tok-123",
		Captcha: TestTokenPrefix + "valid",
	}

	err := m.HandleChallengeResponse(context.Background(), "uuid-1", resp)

	var unavailable *CaptchaUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("expected *CaptchaUnavailableError, got %#v", err)
	}
}

// A push challenge needs no verifier, so an unconfigured manager must still
// handle it rather than refusing everything.
func TestHandleChallengeResponse_PushSucceedsWithNoProviderConfigured(t *testing.T) {
	m := newUnconfiguredManager()
	resp := &ChallengeResponse{Type: ChallengeTypePush, Token: "tok-123"}

	if err := m.HandleChallengeResponse(context.Background(), "uuid-1", resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The field checks run before the provider check, so a malformed submission
// is still reported as malformed rather than as an outage.
func TestHandleChallengeResponse_MissingSolutionOutranksMissingProvider(t *testing.T) {
	m := newUnconfiguredManager()
	resp := &ChallengeResponse{Type: ChallengeTypeCaptcha, Token: "tok-123"}

	err := m.HandleChallengeResponse(context.Background(), "uuid-1", resp)

	var failed *ChallengeFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("expected *ChallengeFailedError, got %#v", err)
	}
}
