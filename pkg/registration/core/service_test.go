package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// recordingTransport records each SendCode invocation so tests can
// assert delivery happened.
type recordingTransport struct {
	calls []recordingCall
	err   error
}

type recordingCall struct {
	destination string
	code        string
}

func (r *recordingTransport) SendCode(_ context.Context, destination, code string, _ ...verification.SendOption) error {
	r.calls = append(r.calls, recordingCall{destination: destination, code: code})
	return r.err
}

func (r *recordingTransport) Name() string { return "recording" }

func newTestService(t *testing.T, cfg Config) (*Service, *recordingTransport) {
	t.Helper()
	store := verification.NewMemoryVerificationSessionStore()
	tr := &recordingTransport{}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Hour
	}
	svc := NewService(store, tr, cfg)
	t.Cleanup(svc.Shutdown)
	return svc, tr
}

func TestCreateSession_HappyPath(t *testing.T) {
	svc, _ := newTestService(t, Config{})
	ctx := context.Background()
	sess, err := svc.CreateSession(ctx, "+15551234567")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.ID == "" {
		t.Error("session ID is empty")
	}
	if sess.Number != "+15551234567" {
		t.Errorf("Number = %q", sess.Number)
	}
	if sess.Verified {
		t.Error("Verified should be false")
	}
	if !sess.AllowedToRequestCode {
		t.Error("AllowedToRequestCode should be true initially")
	}
}

func TestCreateSession_MaxSessions(t *testing.T) {
	svc, _ := newTestService(t, Config{MaxSessions: 2})
	ctx := context.Background()
	if _, err := svc.CreateSession(ctx, "+15551"); err != nil {
		t.Fatalf("first CreateSession: %v", err)
	}
	if _, err := svc.CreateSession(ctx, "+15552"); err != nil {
		t.Fatalf("second CreateSession: %v", err)
	}
	_, err := svc.CreateSession(ctx, "+15553")
	var capErr *verification.SessionLimitExceededError
	if !errors.As(err, &capErr) {
		t.Errorf("expected *SessionLimitExceededError, got %v", err)
	}
}

func TestSendCode_DispatchesAndUpdatesCooldown(t *testing.T) {
	svc, tr := newTestService(t, Config{
		RequestCodeCooldowns: []time.Duration{0, time.Hour},
	})
	ctx := context.Background()
	sess, err := svc.CreateSession(ctx, "+15551234567")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	updated, err := svc.SendCode(ctx, sess.ID)
	if err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	if len(tr.calls) != 1 {
		t.Errorf("transport calls = %d, want 1", len(tr.calls))
	}
	if tr.calls[0].destination != "+15551234567" {
		t.Errorf("destination = %q", tr.calls[0].destination)
	}
	if updated.CodeRequests != 1 {
		t.Errorf("CodeRequests = %d, want 1", updated.CodeRequests)
	}
	if updated.NextCodeRequestAt.IsZero() {
		t.Error("NextCodeRequestAt should be set after a successful SendCode")
	}

	// Second SendCode inside the 1h cooldown must be rate-limited.
	_, err = svc.SendCode(ctx, sess.ID)
	var rateLimited *verification.RequestCodeRateLimitedError
	if !errors.As(err, &rateLimited) {
		t.Errorf("expected *RequestCodeRateLimitedError, got %v", err)
	}
	if rateLimited.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v, expected > 0", rateLimited.RetryAfter)
	}
}

func TestSendCode_FixedCodeReusedAcrossCalls(t *testing.T) {
	svc, tr := newTestService(t, Config{FixedCode: "111222"})
	ctx := context.Background()
	sess, _ := svc.CreateSession(ctx, "+15551")
	if _, err := svc.SendCode(ctx, sess.ID); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	if tr.calls[0].code != "111222" {
		t.Errorf("code dispatched = %q, want 111222", tr.calls[0].code)
	}
}

func TestSubmitCode_HappyPath(t *testing.T) {
	svc, _ := newTestService(t, Config{FixedCode: "654321"})
	ctx := context.Background()
	sess, _ := svc.CreateSession(ctx, "+15551")
	if _, err := svc.SendCode(ctx, sess.ID); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	verified, err := svc.SubmitCode(ctx, sess.ID, "654321")
	if err != nil {
		t.Fatalf("SubmitCode: %v", err)
	}
	if !verified.Verified {
		t.Error("Verified should be true after successful SubmitCode")
	}
	if verified.Code != "" {
		t.Error("Code should be cleared after successful SubmitCode")
	}
}

func TestSubmitCode_InvalidCodeAdvancesAttempts(t *testing.T) {
	svc, _ := newTestService(t, Config{FixedCode: "888888", MaxAttempts: 3})
	ctx := context.Background()
	sess, _ := svc.CreateSession(ctx, "+15551")
	_, _ = svc.SendCode(ctx, sess.ID)

	_, err := svc.SubmitCode(ctx, sess.ID, "000000")
	var bad *verification.InvalidCodeError
	if !errors.As(err, &bad) {
		t.Errorf("expected *InvalidCodeError, got %v", err)
	}
	got, _ := svc.GetSession(ctx, sess.ID)
	if got.Attempts != 1 {
		t.Errorf("Attempts after bad guess = %d, want 1", got.Attempts)
	}
}

func TestSubmitCode_MaxAttemptsExceeded(t *testing.T) {
	svc, _ := newTestService(t, Config{FixedCode: "777777", MaxAttempts: 1})
	ctx := context.Background()
	sess, _ := svc.CreateSession(ctx, "+15551")
	_, _ = svc.SendCode(ctx, sess.ID)
	_, _ = svc.SubmitCode(ctx, sess.ID, "wrong")
	_, err := svc.SubmitCode(ctx, sess.ID, "wrong-again")
	var cap *verification.MaxAttemptsExceededError
	if !errors.As(err, &cap) {
		t.Errorf("expected *MaxAttemptsExceededError, got %v", err)
	}
}

func TestSubmitCode_ExpiredSession(t *testing.T) {
	svc, _ := newTestService(t, Config{
		FixedCode:  "121212",
		SessionTTL: time.Nanosecond,
		CodeTTL:    time.Nanosecond,
	})
	ctx := context.Background()
	sess, _ := svc.CreateSession(ctx, "+15551")
	_, _ = svc.SendCode(ctx, sess.ID)
	time.Sleep(5 * time.Millisecond)
	_, err := svc.SubmitCode(ctx, sess.ID, "121212")
	var expired *verification.SessionExpiredError
	if !errors.As(err, &expired) {
		t.Errorf("expected *SessionExpiredError, got %v", err)
	}
}

func TestGetSession_NotFound(t *testing.T) {
	svc, _ := newTestService(t, Config{})
	ctx := context.Background()
	_, err := svc.GetSession(ctx, "nonexistent")
	var nf *verification.SessionNotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *SessionNotFoundError, got %v", err)
	}
}

func TestSendCode_SessionNotFound(t *testing.T) {
	svc, _ := newTestService(t, Config{})
	ctx := context.Background()
	_, err := svc.SendCode(ctx, "nonexistent-session")
	var nf *verification.SessionNotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *SessionNotFoundError, got %v", err)
	}
}

func TestSendCode_TransportError(t *testing.T) {
	store := verification.NewMemoryVerificationSessionStore()
	tr := &recordingTransport{err: errors.New("provider unreachable")}
	svc := NewService(store, tr, Config{FixedCode: "999999", CleanupInterval: time.Hour})
	t.Cleanup(svc.Shutdown)
	ctx := context.Background()
	sess, _ := svc.CreateSession(ctx, "+15551")
	_, err := svc.SendCode(ctx, sess.ID)
	var te *verification.TransportError
	if !errors.As(err, &te) {
		t.Errorf("expected *TransportError when transport fails, got %v", err)
	}
}

func TestSubmitCode_CodeExpired(t *testing.T) {
	// Submit without first sending code → Code is "" → CodeExpiredError.
	svc, _ := newTestService(t, Config{})
	ctx := context.Background()
	sess, _ := svc.CreateSession(ctx, "+15551")
	_, err := svc.SubmitCode(ctx, sess.ID, "123456")
	var ce *verification.CodeExpiredError
	if !errors.As(err, &ce) {
		t.Errorf("expected *CodeExpiredError, got %v", err)
	}
}

func TestGetSession_Expired(t *testing.T) {
	svc, _ := newTestService(t, Config{SessionTTL: time.Nanosecond})
	ctx := context.Background()
	sess, _ := svc.CreateSession(ctx, "+15551")
	time.Sleep(5 * time.Millisecond)
	_, err := svc.GetSession(ctx, sess.ID)
	var expired *verification.SessionExpiredError
	if !errors.As(err, &expired) {
		t.Errorf("expected *SessionExpiredError, got %v", err)
	}
}

func TestDefaultConfig_NilCooldownUsesDefault(t *testing.T) {
	// Config{} has nil RequestCodeCooldowns; defaultConfig must apply the default.
	cfg := defaultConfig(Config{})
	if len(cfg.RequestCodeCooldowns) == 0 {
		t.Error("defaultConfig must populate RequestCodeCooldowns when nil")
	}
	if cfg.CodeLength != 6 {
		t.Errorf("CodeLength default = %d, want 6", cfg.CodeLength)
	}
}

func TestNextCooldown_ClampsAtScheduleEnd(t *testing.T) {
	svc, _ := newTestService(t, Config{
		RequestCodeCooldowns: []time.Duration{0, time.Minute, time.Hour},
	})
	// Drive nextCooldown directly via the internal method.
	cases := map[int]time.Duration{
		0: 0,
		1: time.Minute,
		2: time.Hour,
		3: time.Hour, // clamps
		9: time.Hour, // still clamps
	}
	for req, want := range cases {
		if got := svc.nextCooldown(req); got != want {
			t.Errorf("nextCooldown(%d) = %v, want %v", req, got, want)
		}
	}
}
