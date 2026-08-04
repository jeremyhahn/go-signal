package sessionshim

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// stubClient implements registration.Client for shim tests, with knobs
// to inject session state, errors, and capture call counts.
type stubClient struct {
	session   *verification.VerificationSession
	createErr error
	sendErr   error
	submitErr error
	getErr    error
	closed    bool

	createCalls, getCalls, sendCalls, submitCalls int
}

func (s *stubClient) CreateSession(_ context.Context, number string) (*verification.VerificationSession, error) {
	s.createCalls++
	if s.createErr != nil {
		return nil, s.createErr
	}
	if s.session == nil {
		s.session = &verification.VerificationSession{
			ID:                   "test-session",
			Number:               number,
			AllowedToRequestCode: true,
			ExpiresAt:            time.Now().Add(10 * time.Minute),
		}
	}
	return clone(s.session), nil
}

func (s *stubClient) GetSession(_ context.Context, sessionID string) (*verification.VerificationSession, error) {
	s.getCalls++
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.session == nil || s.session.ID != sessionID {
		return nil, &verification.SessionNotFoundError{SessionID: sessionID}
	}
	return clone(s.session), nil
}

func (s *stubClient) SendCode(_ context.Context, sessionID string) (*verification.VerificationSession, error) {
	s.sendCalls++
	if s.sendErr != nil {
		return nil, s.sendErr
	}
	if s.session == nil || s.session.ID != sessionID {
		return nil, &verification.SessionNotFoundError{SessionID: sessionID}
	}
	s.session.CodeRequests++
	return clone(s.session), nil
}

func (s *stubClient) SubmitCode(_ context.Context, sessionID, _ string) (*verification.VerificationSession, error) {
	s.submitCalls++
	if s.submitErr != nil {
		return nil, s.submitErr
	}
	if s.session == nil || s.session.ID != sessionID {
		return nil, &verification.SessionNotFoundError{SessionID: sessionID}
	}
	s.session.Verified = true
	return clone(s.session), nil
}

func (s *stubClient) Close() error {
	s.closed = true
	return nil
}

func clone(v *verification.VerificationSession) *verification.VerificationSession {
	cp := *v
	return &cp
}

func newShimFor(t *testing.T, client *stubClient, checker *captcha.Checker, escalateAfter int) *Shim {
	t.Helper()
	return NewShim(Config{
		Client:                 client,
		CaptchaStore:           NewMemoryCaptchaStore(),
		CaptchaChecker:         checker,
		CaptchaEscalationAfter: escalateAfter,
	})
}

func TestCreateSession_ClearsCaptchaStateForRecycledID(t *testing.T) {
	sc := &stubClient{}
	store := NewMemoryCaptchaStore()
	_ = store.SetRequired(context.Background(), "test-session", time.Now().Add(time.Hour))
	shim := NewShim(Config{Client: sc, CaptchaStore: store})
	got, err := shim.CreateSession(context.Background(), "+15551")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if got.CaptchaRequired {
		t.Error("CaptchaRequired must be cleared for a freshly-created session")
	}
	required, _ := store.Required(context.Background(), got.ID)
	if required {
		t.Error("store still reports required after CreateSession")
	}
}

func TestGetSession_MergesLocalCaptchaState(t *testing.T) {
	sc := &stubClient{session: &verification.VerificationSession{ID: "s1", ExpiresAt: time.Now().Add(time.Hour)}}
	store := NewMemoryCaptchaStore()
	_ = store.SetRequired(context.Background(), "s1", time.Now().Add(time.Hour))
	shim := NewShim(Config{Client: sc, CaptchaStore: store})

	got, err := shim.GetSession(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !got.CaptchaRequired {
		t.Error("expected CaptchaRequired=true from local store merge")
	}
}

func TestSendCode_BlocksWhenLocallyCaptchaRequired(t *testing.T) {
	sc := &stubClient{session: &verification.VerificationSession{ID: "s1", ExpiresAt: time.Now().Add(time.Hour)}}
	store := NewMemoryCaptchaStore()
	_ = store.SetRequired(context.Background(), "s1", time.Now().Add(time.Hour))
	shim := NewShim(Config{Client: sc, CaptchaStore: store})

	_, err := shim.SendCode(context.Background(), "s1")
	var captchaRequired *verification.CaptchaRequiredError
	if !errors.As(err, &captchaRequired) {
		t.Errorf("expected *CaptchaRequiredError, got %v", err)
	}
	if sc.sendCalls != 0 {
		t.Errorf("client.SendCode should not have been called; got %d calls", sc.sendCalls)
	}
}

func TestSendCode_EscalatesAfterThreshold(t *testing.T) {
	// Pre-populate a session so the stub's send call advances
	// CodeRequests; CaptchaEscalationAfter=1 means the FIRST successful
	// send should flip the gate.
	sc := &stubClient{session: &verification.VerificationSession{ID: "s1", ExpiresAt: time.Now().Add(time.Hour)}}
	checker := &captcha.Checker{}
	shim := newShimFor(t, sc, checker, 1)

	got, err := shim.SendCode(context.Background(), "s1")
	if err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	if !got.CaptchaRequired {
		t.Error("expected CaptchaRequired=true after the threshold send")
	}
	// Second SendCode is now blocked locally without hitting the client.
	calls := sc.sendCalls
	_, err = shim.SendCode(context.Background(), "s1")
	if err == nil || sc.sendCalls != calls {
		t.Errorf("second SendCode should be blocked locally; err=%v, calls=%d (was %d)",
			err, sc.sendCalls, calls)
	}
}

func TestSubmitCode_ForwardsThrough(t *testing.T) {
	sc := &stubClient{session: &verification.VerificationSession{ID: "s1", ExpiresAt: time.Now().Add(time.Hour)}}
	shim := newShimFor(t, sc, nil, 0)
	got, err := shim.SubmitCode(context.Background(), "s1", "111222")
	if err != nil {
		t.Fatalf("SubmitCode: %v", err)
	}
	if !got.Verified {
		t.Error("Verified should be true after a successful SubmitCode")
	}
	if sc.submitCalls != 1 {
		t.Errorf("submit calls = %d, want 1", sc.submitCalls)
	}
}

func TestSubmitCaptcha_UnavailableWhenNoChecker(t *testing.T) {
	sc := &stubClient{session: &verification.VerificationSession{ID: "s1", ExpiresAt: time.Now().Add(time.Hour)}}
	shim := newShimFor(t, sc, nil, 0)
	_, err := shim.SubmitCaptcha(context.Background(), "s1", "tok", "1.2.3.4")
	var unavail *verification.CaptchaCheckUnavailableError
	if !errors.As(err, &unavail) {
		t.Errorf("expected *CaptchaCheckUnavailableError, got %v", err)
	}
}

func TestMemoryCaptchaStore_RoundTrip(t *testing.T) {
	store := NewMemoryCaptchaStore()
	ctx := context.Background()
	if err := store.SetRequired(ctx, "a", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetRequired: %v", err)
	}
	ok, _ := store.Required(ctx, "a")
	if !ok {
		t.Error("Required should be true")
	}
	if err := store.Clear(ctx, "a"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	ok, _ = store.Required(ctx, "a")
	if ok {
		t.Error("Required should be false after Clear")
	}
}

func TestMemoryCaptchaStore_ExpiredEntriesAutoPrune(t *testing.T) {
	store := NewMemoryCaptchaStore()
	ctx := context.Background()
	_ = store.SetRequired(ctx, "a", time.Now().Add(-time.Hour))
	ok, _ := store.Required(ctx, "a")
	if ok {
		t.Error("expired entry should report Required=false")
	}
	// Sweep should not touch present entries.
	_ = store.SetRequired(ctx, "b", time.Now().Add(time.Hour))
	_ = store.SetRequired(ctx, "c", time.Now().Add(-time.Hour))
	store.Sweep()
	if ok, _ := store.Required(ctx, "b"); !ok {
		t.Error("b should still be Required after sweep")
	}
	if ok, _ := store.Required(ctx, "c"); ok {
		t.Error("c should not be Required after sweep")
	}
}

func TestShim_Shutdown_ClosesClient(t *testing.T) {
	sc := &stubClient{}
	shim := newShimFor(t, sc, nil, 0)
	shim.Shutdown()
	if !sc.closed {
		t.Error("Shutdown must propagate Close to the client")
	}
}

func TestNewShim_PanicsWithoutClient(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	NewShim(Config{CaptchaStore: NewMemoryCaptchaStore()})
}

func TestNewShim_PanicsWithoutCaptchaStore(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	NewShim(Config{Client: &stubClient{}})
}

func TestNewShim_NegativeEscalationDisablesGating(t *testing.T) {
	// Negative CaptchaEscalationAfter must be normalised to 0, meaning
	// captcha gating is disabled regardless of send count.
	sc := &stubClient{session: &verification.VerificationSession{ID: "s1", ExpiresAt: time.Now().Add(time.Hour)}}
	checker := &captcha.Checker{}
	shim := NewShim(Config{
		Client:                 sc,
		CaptchaStore:           NewMemoryCaptchaStore(),
		CaptchaChecker:         checker,
		CaptchaEscalationAfter: -1,
	})
	// Send should not escalate captcha even though checker is wired.
	got, err := shim.SendCode(context.Background(), "s1")
	if err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	if got.CaptchaRequired {
		t.Error("captcha should NOT be required when CaptchaEscalationAfter < 0")
	}
}

func TestCreateSession_ClientError(t *testing.T) {
	sc := &stubClient{createErr: errors.New("backend unavailable")}
	shim := newShimFor(t, sc, nil, 0)
	_, err := shim.CreateSession(context.Background(), "+15551")
	if err == nil {
		t.Error("expected error when client.CreateSession fails")
	}
}

func TestGetSession_ClientError(t *testing.T) {
	sc := &stubClient{getErr: errors.New("lookup failed")}
	shim := newShimFor(t, sc, nil, 0)
	_, err := shim.GetSession(context.Background(), "s1")
	if err == nil {
		t.Error("expected error when client.GetSession fails")
	}
}

func TestSendCode_ClientError(t *testing.T) {
	sc := &stubClient{
		session: &verification.VerificationSession{ID: "s1", ExpiresAt: time.Now().Add(time.Hour)},
		sendErr: errors.New("rpc failed"),
	}
	shim := newShimFor(t, sc, nil, 0)
	_, err := shim.SendCode(context.Background(), "s1")
	if err == nil {
		t.Error("expected error when client.SendCode fails")
	}
}

func TestSubmitCaptcha_GetSessionError(t *testing.T) {
	sc := &stubClient{getErr: errors.New("backend down")}
	checker := &captcha.Checker{Providers: map[string]captcha.CaptchaVerifier{
		"test": captcha.NewTestVerifier(captcha.TestVerifierConfig{}),
	}}
	shim := NewShim(Config{Client: sc, CaptchaStore: NewMemoryCaptchaStore(), CaptchaChecker: checker})
	_, err := shim.SubmitCaptcha(context.Background(), "s1", "tok", "1.2.3.4")
	if err == nil {
		t.Error("expected error when GetSession fails")
	}
}

func TestSubmitCaptcha_SessionExpired(t *testing.T) {
	sc := &stubClient{session: &verification.VerificationSession{
		ID:        "s1",
		ExpiresAt: time.Now().Add(-time.Minute), // expired
	}}
	checker := &captcha.Checker{Providers: map[string]captcha.CaptchaVerifier{
		"test": captcha.NewTestVerifier(captcha.TestVerifierConfig{}),
	}}
	shim := NewShim(Config{Client: sc, CaptchaStore: NewMemoryCaptchaStore(), CaptchaChecker: checker})
	_, err := shim.SubmitCaptcha(context.Background(), "s1", "tok", "1.2.3.4")
	var expired *verification.SessionExpiredError
	if !errors.As(err, &expired) {
		t.Errorf("expected *SessionExpiredError, got %v", err)
	}
}

func TestSubmitCaptcha_InvalidToken_CaptchaRejected(t *testing.T) {
	sc := &stubClient{session: &verification.VerificationSession{
		ID:        "s1",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	checker := &captcha.Checker{Providers: map[string]captcha.CaptchaVerifier{
		"test": captcha.NewTestVerifier(captcha.TestVerifierConfig{}),
	}}
	shim := NewShim(Config{Client: sc, CaptchaStore: NewMemoryCaptchaStore(), CaptchaChecker: checker})
	// Token without the required provider.key.action.token format → InvalidTokenFormatError.
	_, err := shim.SubmitCaptcha(context.Background(), "s1", "not-a-token", "1.2.3.4")
	var rejected *verification.CaptchaRejectedError
	if !errors.As(err, &rejected) {
		t.Errorf("expected *CaptchaRejectedError for malformed token, got %v", err)
	}
}

func TestSubmitCaptcha_UnknownProvider_CaptchaRejected(t *testing.T) {
	sc := &stubClient{session: &verification.VerificationSession{
		ID:        "s1",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	checker := &captcha.Checker{Providers: map[string]captcha.CaptchaVerifier{
		"test": captcha.NewTestVerifier(captcha.TestVerifierConfig{}),
	}}
	shim := NewShim(Config{Client: sc, CaptchaStore: NewMemoryCaptchaStore(), CaptchaChecker: checker})
	// Unknown provider "recaptcha" not in the Providers map.
	_, err := shim.SubmitCaptcha(context.Background(), "s1", "recaptcha.sitekey.challenge.token", "1.2.3.4")
	var rejected *verification.CaptchaRejectedError
	if !errors.As(err, &rejected) {
		t.Errorf("expected *CaptchaRejectedError for unknown provider, got %v", err)
	}
}

func TestSubmitCaptcha_ProviderRejects_CaptchaRejected(t *testing.T) {
	sc := &stubClient{session: &verification.VerificationSession{
		ID:        "s1",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	// TestVerifier rejects any token that doesn't start with "test-captcha-".
	checker := &captcha.Checker{Providers: map[string]captcha.CaptchaVerifier{
		"test": captcha.NewTestVerifier(captcha.TestVerifierConfig{}),
	}}
	shim := NewShim(Config{Client: sc, CaptchaStore: NewMemoryCaptchaStore(), CaptchaChecker: checker})
	// "invalid-token" does not start with "test-captcha-" → Success=false.
	_, err := shim.SubmitCaptcha(context.Background(), "s1", "test.sitekey.challenge.invalid-token", "1.2.3.4")
	var rejected *verification.CaptchaRejectedError
	if !errors.As(err, &rejected) {
		t.Errorf("expected *CaptchaRejectedError when provider rejects, got %v", err)
	}
}

func TestSubmitCaptcha_Success(t *testing.T) {
	sc := &stubClient{session: &verification.VerificationSession{
		ID:              "s1",
		ExpiresAt:       time.Now().Add(time.Hour),
		CaptchaRequired: true,
	}}
	store := NewMemoryCaptchaStore()
	_ = store.SetRequired(context.Background(), "s1", time.Now().Add(time.Hour))
	checker := &captcha.Checker{Providers: map[string]captcha.CaptchaVerifier{
		"test": captcha.NewTestVerifier(captcha.TestVerifierConfig{}),
	}}
	shim := NewShim(Config{Client: sc, CaptchaStore: store, CaptchaChecker: checker})
	// "test-captcha-ok" starts with "test-captcha-" → accepted.
	got, err := shim.SubmitCaptcha(context.Background(), "s1", "test.sitekey.challenge.test-captcha-ok", "1.2.3.4")
	if err != nil {
		t.Fatalf("SubmitCaptcha: %v", err)
	}
	if got.CaptchaRequired {
		t.Error("CaptchaRequired should be cleared after successful submission")
	}
	// Store should also be cleared.
	required, _ := store.Required(context.Background(), "s1")
	if required {
		t.Error("store should report not-required after successful captcha")
	}
}
