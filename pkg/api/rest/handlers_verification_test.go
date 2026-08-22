package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/extservice/registration/inprocess"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/registration/sessionshim"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// newTestShim wires a sessionshim.Shim atop a freshly constructed
// core.Service for tests. coreCfg controls the lower-half behaviour
// (CodeLength, CodeTTL, MaxAttempts, MaxSessions, SessionTTL,
// CleanupInterval, RequestCodeCooldowns, FixedCode). captchaChecker,
// escalateAfter and scoreThreshold control the chat-server-side
// captcha gate exactly as the pre-split *verification.Manager did.
// The core's background cleanup goroutine is wired through t.Cleanup.
func newTestShim(
	t *testing.T,
	store verification.VerificationSessionStore,
	transport verification.VerificationTransport,
	coreCfg core.Config,
	captchaChecker *captcha.Checker,
	escalateAfter int,
	scoreThreshold float64,
) *sessionshim.Shim {
	t.Helper()
	svc := core.NewService(store, transport, coreCfg)
	t.Cleanup(svc.Shutdown)
	return sessionshim.NewShim(sessionshim.Config{
		Client:                 inprocess.New(svc),
		CaptchaStore:           sessionshim.NewMemoryCaptchaStore(),
		CaptchaChecker:         captchaChecker,
		CaptchaEscalationAfter: escalateAfter,
		CaptchaScoreThreshold:  scoreThreshold,
	})
}

// createSession is a test helper that POSTs to /v1/verification/session and
// returns the parsed response. It fatals on any unexpected status or decode
// error.
func createSession(t *testing.T, s *Server, number string) VerificationSessionResponse {
	t.Helper()
	body := fmt.Sprintf(`{"number":%q,"transport":"sms"}`, number)
	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("createSession: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp VerificationSessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("createSession: unmarshal error: %v", err)
	}
	return resp
}

// requestCode triggers POST /v1/verification/session/{id}/code and returns the
// HTTP status code. The noopVerificationTransport will capture the generated
// code so tests can retrieve it via transport.LastCode.
func requestCode(t *testing.T, s *Server, sessionID string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session/"+sessionID+"/code", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	return rr.Code
}

// submitCode calls PUT /v1/verification/session/{id}/code with the given code
// and returns the recorder so the caller can inspect both status and body.
func submitCode(t *testing.T, s *Server, sessionID, code string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"code":%q}`, code)
	req := httptest.NewRequest(http.MethodPut, "/v1/verification/session/"+sessionID+"/code", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

// newTestServerWithCustomVerification creates a full test server wired to a
// caller-provided sessionshim.Shim instead of the default one. This allows
// tests to inject custom TTLs, session limits, and cleanup intervals.
func newTestServerWithCustomVerification(t *testing.T, mgr *sessionshim.Shim) *Server {
	t.Helper()
	s, _ := newTestServerWithVerification(t)
	s.verification = mgr
	return s
}

// --------------------------------------------------------------------------
// handleCreateVerificationSession
// --------------------------------------------------------------------------

func TestHandleCreateVerificationSession_Success(t *testing.T) {
	s := newTestServer(t)

	body := `{"number":"+15551234567","transport":"sms"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp VerificationSessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.ID == "" {
		t.Error("expected non-empty session ID")
	}
	if !resp.AllowedToRequestCode {
		t.Error("expected AllowedToRequestCode true")
	}
	if resp.Verified {
		t.Error("expected Verified false")
	}
}

func TestHandleCreateVerificationSession_InvalidBody(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session", strings.NewReader("bad"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleCreateVerificationSession_MissingNumber(t *testing.T) {
	s := newTestServer(t)

	body := `{"number":"","transport":"sms"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestHandleCreateVerificationSession_MaxSessions verifies that once the
// session limit is reached the endpoint returns HTTP 429.
func TestHandleCreateVerificationSession_MaxSessions(t *testing.T) {
	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	verificationMgr := newTestShim(t, store, transport, core.Config{
		CodeLength:  6,
		CodeTTL:     5 * time.Minute,
		MaxAttempts: 3,
		MaxSessions: 2, // cap at 2 so the test runs fast
		SessionTTL:  10 * time.Minute,
	}, nil, 0, 0)

	s := newTestServerWithCustomVerification(t, verificationMgr)

	// Fill to the cap.
	createSession(t, s, "+15551111111")
	createSession(t, s, "+15552222222")

	// Next request must be rejected with 429.
	body := `{"number":"+15553333333","transport":"sms"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleCreateVerificationSession_ServiceUnavailable verifies the
// 503 path when no verification manager is wired.
func TestHandleCreateVerificationSession_ServiceUnavailable(t *testing.T) {
	s := newTestServer(t)
	s.verification = nil

	body := `{"number":"+15551234567","transport":"sms"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetVerificationSession
// --------------------------------------------------------------------------

func TestHandleGetVerificationSession_Success(t *testing.T) {
	s := newTestServer(t)

	// Create a session first.
	createBody := `{"number":"+15551234567","transport":"sms"}`
	createReq := httptest.NewRequest(http.MethodPost, "/v1/verification/session", strings.NewReader(createBody))
	createRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(createRR, createReq)

	var createResp VerificationSessionResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Get the session.
	getReq := httptest.NewRequest(http.MethodGet, "/v1/verification/session/"+createResp.ID, nil)
	getRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", getRR.Code, getRR.Body.String())
	}

	var resp VerificationSessionResponse
	if err := json.Unmarshal(getRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.ID != createResp.ID {
		t.Errorf("expected session ID %s, got %s", createResp.ID, resp.ID)
	}
}

func TestHandleGetVerificationSession_NotFound(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/verification/session/nonexistent", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// TestHandleGetVerificationSession_ExpiredSessionPreventsCodeSend verifies
// that once a session has expired, requesting a code returns 410 Gone.
func TestHandleGetVerificationSession_ExpiredSessionPreventsCodeSend(t *testing.T) {
	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	// Use a 1ns TTL so the session is expired immediately after creation.
	verificationMgr := newTestShim(t, store, transport, core.Config{
		CodeLength:  6,
		CodeTTL:     5 * time.Minute,
		MaxAttempts: 3,
		SessionTTL:  time.Nanosecond,
	}, nil, 0, 0)

	s := newTestServerWithCustomVerification(t, verificationMgr)
	sess := createSession(t, s, "+15551234567")

	// Let the session expire.
	time.Sleep(5 * time.Millisecond)

	// SendCode must reject the expired session with 410 Gone.
	statusCode := requestCode(t, s, sess.ID)
	if statusCode != http.StatusGone {
		t.Errorf("expected 410 Gone for expired session code request, got %d", statusCode)
	}
}

// TestHandleGetVerificationSession_ServiceUnavailable covers the 503 path.
func TestHandleGetVerificationSession_ServiceUnavailable(t *testing.T) {
	s := newTestServer(t)
	s.verification = nil

	req := httptest.NewRequest(http.MethodGet, "/v1/verification/session/someid", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleRequestVerificationCode
// --------------------------------------------------------------------------

func TestHandleRequestVerificationCode_Success(t *testing.T) {
	s := newTestServer(t)

	// Create a session first.
	createBody := `{"number":"+15551234567","transport":"sms"}`
	createReq := httptest.NewRequest(http.MethodPost, "/v1/verification/session", strings.NewReader(createBody))
	createRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(createRR, createReq)

	var createResp VerificationSessionResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Request code.
	codeReq := httptest.NewRequest(http.MethodPost, "/v1/verification/session/"+createResp.ID+"/code", nil)
	codeRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(codeRR, codeReq)

	if codeRR.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", codeRR.Code)
	}
}

func TestHandleRequestVerificationCode_SessionNotFound(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session/nonexistent/code", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// TestHandleRequestVerificationCode_ExpiredSession verifies HTTP 410 when the
// session has exceeded its TTL at the point SendCode is called.
func TestHandleRequestVerificationCode_ExpiredSession(t *testing.T) {
	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	verificationMgr := newTestShim(t, store, transport, core.Config{
		CodeLength:  6,
		CodeTTL:     5 * time.Minute,
		MaxAttempts: 3,
		SessionTTL:  time.Nanosecond,
	}, nil, 0, 0)

	s := newTestServerWithCustomVerification(t, verificationMgr)
	sess := createSession(t, s, "+15551234567")

	time.Sleep(5 * time.Millisecond)

	statusCode := requestCode(t, s, sess.ID)
	if statusCode != http.StatusGone {
		t.Errorf("expected 410 Gone, got %d", statusCode)
	}
}

// TestHandleRequestVerificationCode_RateLimited covers the 429 path with the
// Retry-After header populated from RequestCodeRateLimitedError.RetryAfter.
func TestHandleRequestVerificationCode_RateLimited(t *testing.T) {
	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	verificationMgr := newTestShim(t, store, transport, core.Config{
		CodeLength: 6,
		CodeTTL:    5 * time.Minute,
		// Force the second SendCode into the cooldown branch immediately.
		RequestCodeCooldowns: []time.Duration{0, 1 * time.Hour},
	}, nil, 0, 0)

	s := newTestServerWithCustomVerification(t, verificationMgr)
	sess := createSession(t, s, "+15555550100")

	// First request succeeds.
	if code := requestCode(t, s, sess.ID); code != http.StatusOK {
		t.Fatalf("first requestCode: expected 200, got %d", code)
	}

	// Second request must be rate-limited.
	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session/"+sess.ID+"/code", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
	if retry := rr.Header().Get("Retry-After"); retry == "" || retry == "0" {
		t.Errorf("expected non-zero Retry-After, got %q", retry)
	}
}

// TestHandleRequestVerificationCode_ServiceUnavailable covers the 503 path.
func TestHandleRequestVerificationCode_ServiceUnavailable(t *testing.T) {
	s := newTestServer(t)
	s.verification = nil

	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session/someid/code", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleSubmitVerificationCode
// --------------------------------------------------------------------------

// TestHandleSubmitVerificationCode_Success exercises the full happy path:
// create session -> request code -> submit the captured code -> verified.
func TestHandleSubmitVerificationCode_Success(t *testing.T) {
	s, transport := newTestServerWithVerification(t)

	sess := createSession(t, s, "+15551234567")

	if status := requestCode(t, s, sess.ID); status != http.StatusOK {
		t.Fatalf("requestCode: expected 200, got %d", status)
	}

	code := transport.LastCode("+15551234567")
	if code == "" {
		t.Fatal("transport did not capture any code")
	}

	rr := submitCode(t, s, sess.ID, code)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp VerificationSessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if !resp.Verified {
		t.Error("expected session to be verified")
	}
}

func TestHandleSubmitVerificationCode_SessionNotFound(t *testing.T) {
	s := newTestServer(t)

	body := `{"code":"123456"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/verification/session/nonexistent/code", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleSubmitVerificationCode_InvalidBody(t *testing.T) {
	s := newTestServer(t)

	// Create a session.
	createBody := `{"number":"+15551234567","transport":"sms"}`
	createReq := httptest.NewRequest(http.MethodPost, "/v1/verification/session", strings.NewReader(createBody))
	createRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(createRR, createReq)

	var createResp VerificationSessionResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/v1/verification/session/"+createResp.ID+"/code", strings.NewReader("bad"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestHandleSubmitVerificationCode_MissingCode verifies that submitting an
// empty code body returns 400.
func TestHandleSubmitVerificationCode_MissingCode(t *testing.T) {
	s := newTestServer(t)
	sess := createSession(t, s, "+15551234567")

	rr := submitCode(t, s, sess.ID, "")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// TestHandleSubmitVerificationCode_InvalidCode verifies that submitting a
// wrong code returns 403 Forbidden.
func TestHandleSubmitVerificationCode_InvalidCode(t *testing.T) {
	s, _ := newTestServerWithVerification(t)
	sess := createSession(t, s, "+15551234567")

	if status := requestCode(t, s, sess.ID); status != http.StatusOK {
		t.Fatalf("requestCode: expected 200, got %d", status)
	}

	rr := submitCode(t, s, sess.ID, "000000")
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleSubmitVerificationCode_ExpiredSession verifies that trying to
// submit a code for a session that expired after code request returns 410.
func TestHandleSubmitVerificationCode_ExpiredSession(t *testing.T) {
	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	verificationMgr := newTestShim(t, store, transport, core.Config{
		CodeLength:  6,
		CodeTTL:     time.Nanosecond,
		MaxAttempts: 3,
		SessionTTL:  time.Nanosecond,
	}, nil, 0, 0)

	s := newTestServerWithCustomVerification(t, verificationMgr)
	sess := createSession(t, s, "+15551234567")

	time.Sleep(5 * time.Millisecond)

	rr := submitCode(t, s, sess.ID, "123456")
	if rr.Code != http.StatusGone && rr.Code != http.StatusNotFound {
		t.Errorf("expected 410 or 404 for expired session, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleSubmitVerificationCode_MaxAttempts verifies that exceeding the
// attempt limit returns 429.
func TestHandleSubmitVerificationCode_MaxAttempts(t *testing.T) {
	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	verificationMgr := newTestShim(t, store, transport, core.Config{
		CodeLength:  6,
		CodeTTL:     5 * time.Minute,
		MaxAttempts: 1, // allow only one attempt
		SessionTTL:  10 * time.Minute,
	}, nil, 0, 0)

	s := newTestServerWithCustomVerification(t, verificationMgr)
	sess := createSession(t, s, "+15551234567")

	if status := requestCode(t, s, sess.ID); status != http.StatusOK {
		t.Fatalf("requestCode: expected 200, got %d", status)
	}

	// First attempt: wrong code (consumes the single allowed attempt).
	submitCode(t, s, sess.ID, "000000")

	// Second attempt: any code should now be 429.
	rr := submitCode(t, s, sess.ID, "000000")
	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleSubmitVerificationCode_ServiceUnavailable covers the 503 path.
func TestHandleSubmitVerificationCode_ServiceUnavailable(t *testing.T) {
	s := newTestServer(t)
	s.verification = nil

	body := `{"code":"123456"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/verification/session/someid/code", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// Cleanup goroutine
// --------------------------------------------------------------------------

// TestVerificationManager_CleanupRemovesExpiredSessions verifies that the
// background cleanup goroutine evicts expired sessions from the store.
func TestVerificationManager_CleanupRemovesExpiredSessions(t *testing.T) {
	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	verificationMgr := newTestShim(t, store, transport, core.Config{
		CodeLength:      6,
		CodeTTL:         time.Nanosecond,
		MaxAttempts:     3,
		SessionTTL:      time.Nanosecond,
		CleanupInterval: 10 * time.Millisecond, // fast cleanup for tests
	}, nil, 0, 0)

	s := newTestServerWithCustomVerification(t, verificationMgr)

	// Create a session so there is something to clean up.
	createSession(t, s, "+15551234567")

	// Confirm the session exists in the store immediately.
	count, err := store.Count(t.Context())
	if err != nil {
		t.Fatalf("store.Count: %v", err)
	}
	if count == 0 {
		t.Fatal("expected session to exist in store after creation")
	}

	// Wait for the session to expire and the cleanup goroutine to run.
	deadline := time.Now().Add(500 * time.Millisecond)
	var finalCount int
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		finalCount, err = store.Count(t.Context())
		if err != nil {
			t.Fatalf("store.Count: %v", err)
		}
		if finalCount == 0 {
			break
		}
	}

	if finalCount != 0 {
		t.Errorf("expected 0 sessions after cleanup, got %d", finalCount)
	}
}

// --------------------------------------------------------------------------
// Concurrent session creation and lookup
// --------------------------------------------------------------------------

// TestVerificationSession_ConcurrentCreateAndLookup exercises concurrent
// session creation and lookup under the race detector to verify there are no
// data races in the verification layer.
func TestVerificationSession_ConcurrentCreateAndLookup(t *testing.T) {
	s, _ := newTestServerWithVerification(t)

	const goroutines = 20
	var wg sync.WaitGroup
	ids := make([]string, goroutines)
	var mu sync.Mutex

	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			number := fmt.Sprintf("+1555%07d", idx)
			sess := createSession(t, s, number)
			mu.Lock()
			ids[idx] = sess.ID
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// All sessions should be retrievable.
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			mu.Lock()
			id := ids[idx]
			mu.Unlock()
			req := httptest.NewRequest(http.MethodGet, "/v1/verification/session/"+id, nil)
			rr := httptest.NewRecorder()
			s.httpServer.Handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("goroutine %d: expected 200, got %d", idx, rr.Code)
			}
		}(i)
	}
	wg.Wait()
}

// --------------------------------------------------------------------------
// End-to-end expiry test
// --------------------------------------------------------------------------

// TestHandleSubmitVerificationCode_EndToEndExpiry creates a session, waits
// for it to expire, and then verifies that verification is rejected.
func TestHandleSubmitVerificationCode_EndToEndExpiry(t *testing.T) {
	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	verificationMgr := newTestShim(t, store, transport, core.Config{
		CodeLength:  6,
		CodeTTL:     time.Nanosecond,
		MaxAttempts: 3,
		SessionTTL:  time.Nanosecond,
	}, nil, 0, 0)

	s := newTestServerWithCustomVerification(t, verificationMgr)
	sess := createSession(t, s, "+15551234567")

	// Session expires immediately; wait briefly to guarantee it.
	time.Sleep(5 * time.Millisecond)

	// Both code request and code submission should be rejected.
	statusCode := requestCode(t, s, sess.ID)
	if statusCode != http.StatusGone && statusCode != http.StatusNotFound {
		t.Errorf("requestCode after expiry: expected 410 or 404, got %d", statusCode)
	}

	rr := submitCode(t, s, sess.ID, "123456")
	if rr.Code != http.StatusGone && rr.Code != http.StatusNotFound {
		t.Errorf("submitCode after expiry: expected 410 or 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// PATCH /v1/verification/session/{id}  +  captcha escalation gate
// --------------------------------------------------------------------------

// captchaStubVerifier is a tiny captcha.CaptchaVerifier used by the REST
// PATCH tests; it returns a canned success/failure result.
type captchaStubVerifier struct {
	success bool
	score   float64
}

func (c *captchaStubVerifier) Verify(_ context.Context, _, _, _ string) (*captcha.VerifyResult, error) {
	return &captcha.VerifyResult{Success: c.success, Score: c.score}, nil
}

// buildCaptchaCheckerWithProvider constructs a captcha.Checker wired to a
// single stub provider keyed under "recaptcha".
func buildCaptchaCheckerWithProvider(v captcha.CaptchaVerifier) *captcha.Checker {
	return &captcha.Checker{Providers: map[string]captcha.CaptchaVerifier{"recaptcha": v}}
}

// newTestServerWithCaptchaEscalation creates a test server whose
// sessionshim.Shim escalates to CaptchaRequired after the first
// successful SendCode.
func newTestServerWithCaptchaEscalation(t *testing.T, checker *captcha.Checker) *Server {
	t.Helper()
	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	mgr := newTestShim(t, store, transport, core.Config{
		FixedCode:            "111111",
		CodeTTL:              5 * time.Minute,
		RequestCodeCooldowns: []time.Duration{0, 0},
	}, checker, 1, 0)
	s, _ := newTestServerWithVerification(t)
	s.verification = mgr
	s.captchaChecker = checker
	if checker != nil {
		s.regCaptcha = captcha.NewRegistrationCaptchaManager(checker)
	}
	return s
}

func TestHandleRequestVerificationCode_CaptchaRequiredReturns409(t *testing.T) {
	s := newTestServerWithCaptchaEscalation(t, buildCaptchaCheckerWithProvider(&captchaStubVerifier{success: true, score: 0.9}))
	sess := createSession(t, s, "+15555550500")

	// First request goes through.
	if code := requestCode(t, s, sess.ID); code != http.StatusOK {
		t.Fatalf("first requestCode: expected 200, got %d", code)
	}

	// Second request is gated by CaptchaRequired and returns 409.
	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session/"+sess.ID+"/code", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp VerificationSessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode 409 body: %v", err)
	}
	if len(resp.RequestedInformation) != 1 || resp.RequestedInformation[0] != "captcha" {
		t.Errorf(`expected requestedInformation=["captcha"], got %+v`, resp.RequestedInformation)
	}
}

func TestHandleUpdateVerificationSession_ClearsCaptchaRequired(t *testing.T) {
	s := newTestServerWithCaptchaEscalation(t, buildCaptchaCheckerWithProvider(&captchaStubVerifier{success: true, score: 0.9}))
	sess := createSession(t, s, "+15555550501")

	// Drive escalation.
	if code := requestCode(t, s, sess.ID); code != http.StatusOK {
		t.Fatalf("first requestCode: %d", code)
	}
	if code := requestCode(t, s, sess.ID); code != http.StatusConflict {
		t.Fatalf("expected 409 after escalation: got %d", code)
	}

	// PATCH with a valid challenge captcha clears the flag.
	body := `{"captcha":"recaptcha.sk.challenge.opaque"}`
	patch := httptest.NewRequest(http.MethodPatch, "/v1/verification/session/"+sess.ID, strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, patch)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from PATCH, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp VerificationSessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode PATCH body: %v", err)
	}
	if len(resp.RequestedInformation) != 0 {
		t.Errorf("captchaRequired should be cleared; got requestedInformation=%v", resp.RequestedInformation)
	}

	// Next SendCode succeeds.
	if code := requestCode(t, s, sess.ID); code != http.StatusOK {
		t.Errorf("requestCode after PATCH: expected 200, got %d", code)
	}
}

func TestHandleUpdateVerificationSession_RejectsBadCaptcha(t *testing.T) {
	s := newTestServerWithCaptchaEscalation(t, buildCaptchaCheckerWithProvider(&captchaStubVerifier{success: false}))
	sess := createSession(t, s, "+15555550502")

	body := `{"captcha":"recaptcha.sk.challenge.opaque"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/verification/session/"+sess.ID, strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for rejected captcha, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUpdateVerificationSession_NoBodyReturnsCurrent(t *testing.T) {
	s := newTestServerWithCaptchaEscalation(t, buildCaptchaCheckerWithProvider(&captchaStubVerifier{success: true}))
	sess := createSession(t, s, "+15555550503")

	req := httptest.NewRequest(http.MethodPatch, "/v1/verification/session/"+sess.ID, strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUpdateVerificationSession_NoCheckerReturns503(t *testing.T) {
	// Deployment without a captcha checker — PATCH with a captcha must
	// return 503 (and never silently accept it).
	s := newTestServer(t)
	body := `{"number":"+15555550504","transport":"sms"}`
	createReq := httptest.NewRequest(http.MethodPost, "/v1/verification/session", strings.NewReader(body))
	createRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(createRR, createReq)
	var resp VerificationSessionResponse
	if err := json.Unmarshal(createRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create body: %v", err)
	}

	patch := httptest.NewRequest(http.MethodPatch, "/v1/verification/session/"+resp.ID,
		strings.NewReader(`{"captcha":"recaptcha.sk.challenge.tok"}`))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, patch)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUpdateVerificationSession_SessionNotFound(t *testing.T) {
	s := newTestServerWithCaptchaEscalation(t, buildCaptchaCheckerWithProvider(&captchaStubVerifier{success: true}))
	req := httptest.NewRequest(http.MethodPatch, "/v1/verification/session/missing-id",
		strings.NewReader(`{"captcha":"recaptcha.sk.challenge.tok"}`))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleUpdateVerificationSession_NoCaptcha_SessionNotFound verifies that
// a PATCH with no captcha field for a missing session returns 404.
// This exercises the req.Captcha == "" path → GetSession → notFound.
func TestHandleUpdateVerificationSession_NoCaptcha_SessionNotFound(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPatch, "/v1/verification/session/nonexistent-id",
		strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent session with no captcha, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleUpdateVerificationSession_InvalidBody verifies that an invalid
// JSON body returns 400.
func TestHandleUpdateVerificationSession_InvalidBody(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPatch, "/v1/verification/session/some-id",
		strings.NewReader(`{bad json`))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid body, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleRequestVerificationCode_AlreadyVerified covers the re-registration
// flow: the client reuses its stored session after verifying, and Java answers
// 409 with the session so it can proceed straight to registration. Before this
// mapping existed the still-armed cooldown produced a 429, which libsignal
// surfaces as RegistrationRetryException and no amount of waiting resolves.
func TestHandleRequestVerificationCode_AlreadyVerified(t *testing.T) {
	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	verificationMgr := newTestShim(t, store, transport, core.Config{
		CodeLength: 6,
		CodeTTL:    5 * time.Minute,
		FixedCode:  "123456",
		// The cooldown stays armed, so a missing verified check would
		// surface this as 429 rather than 409.
		RequestCodeCooldowns: []time.Duration{0, 1 * time.Hour},
	}, nil, 0, 0)

	s := newTestServerWithCustomVerification(t, verificationMgr)
	sess := createSession(t, s, "+15555550101")

	if code := requestCode(t, s, sess.ID); code != http.StatusOK {
		t.Fatalf("requestCode: expected 200, got %d", code)
	}
	if rr := submitCode(t, s, sess.ID, "123456"); rr.Code != http.StatusOK {
		t.Fatalf("submitCode: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session/"+sess.ID+"/code", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}

	// The body carries the session so the client can read verified=true.
	var resp VerificationSessionResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal 409 body: %v", err)
	}
	if !resp.Verified {
		t.Error("409 body should report the session as verified")
	}
	if resp.ID != sess.ID {
		t.Errorf("409 body session id = %q, want %q", resp.ID, sess.ID)
	}
}

// failOnNthGetStore passes Get through until armed, then fails the next Get.
// The arming is what makes the test target the RELOAD specifically: SendCode
// reads the session first and must succeed so it can report
// SessionAlreadyVerifiedError, and only the handler's follow-up reload fails.
// A store that failed every Get would make SendCode itself fail and never
// reach the branch under test.
type failOnNthGetStore struct {
	verification.VerificationSessionStore
	mu        sync.Mutex
	remaining int  // Gets to let through before failing
	armed     bool //nolint:unused // guarded by mu
	err       error
}

func (f *failOnNthGetStore) armAfter(n int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remaining, f.err, f.armed = n, err, true
}

func (f *failOnNthGetStore) Get(ctx context.Context, id string) (*verification.VerificationSession, error) {
	f.mu.Lock()
	if f.armed {
		if f.remaining <= 0 {
			err := f.err
			f.mu.Unlock()
			return nil, err
		}
		f.remaining--
	}
	f.mu.Unlock()
	return f.VerificationSessionStore.Get(ctx, id)
}

// TestHandleRequestVerificationCode_ReloadFailureIsNotAConflict is the
// regression test for the second finding on #28.
//
// The already-verified branch answered 409 whether or not the session reload
// succeeded, so a storage or transport failure was reported to the client as
// a well-formed protocol outcome about a session nobody could read. The
// client then acts on that. A failure to obtain the session is not an answer
// about the session, so it is now a 500.
func TestHandleRequestVerificationCode_ReloadFailureIsNotAConflict(t *testing.T) {
	transport := newNoopVerificationTransport()
	backing := verification.NewMemoryVerificationSessionStore()
	store := &failOnNthGetStore{VerificationSessionStore: backing}

	verificationMgr := newTestShim(t, store, transport, core.Config{
		CodeLength:           6,
		CodeTTL:              5 * time.Minute,
		FixedCode:            "123456",
		RequestCodeCooldowns: []time.Duration{0, 1 * time.Hour},
	}, nil, 0, 0)

	s := newTestServerWithCustomVerification(t, verificationMgr)
	sess := createSession(t, s, "+15555550199")

	if code := requestCode(t, s, sess.ID); code != http.StatusOK {
		t.Fatalf("requestCode: expected 200, got %d", code)
	}
	if rr := submitCode(t, s, sess.ID, "123456"); rr.Code != http.StatusOK {
		t.Fatalf("submitCode: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Let SendCode's own read through, then fail the handler's reload.
	store.armAfter(1, errors.New("session store is unavailable"))

	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session/"+sess.ID+"/code", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when the session cannot be reloaded, got %d: %s",
			rr.Code, rr.Body.String())
	}
}

// TestHandleRequestVerificationCode_ReloadFailureDoesNotLogTheSessionID pins
// the security fix from #28 round 3.
//
// A verified session id is the bearer credential POST /v1/registration accepts
// as proof of verification (enforceVerifiedSession), so writing it to logs
// turns log access into account takeover for any number with a live session.
// The reload-failure path logged it as a correlation attribute.
func TestHandleRequestVerificationCode_ReloadFailureDoesNotLogTheSessionID(t *testing.T) {
	transport := newNoopVerificationTransport()
	backing := verification.NewMemoryVerificationSessionStore()
	store := &failOnNthGetStore{VerificationSessionStore: backing}

	verificationMgr := newTestShim(t, store, transport, core.Config{
		CodeLength:           6,
		CodeTTL:              5 * time.Minute,
		FixedCode:            "123456",
		RequestCodeCooldowns: []time.Duration{0, 1 * time.Hour},
	}, nil, 0, 0)

	s := newTestServerWithCustomVerification(t, verificationMgr)

	var logs bytes.Buffer
	s.logger = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	sess := createSession(t, s, "+15555550200")
	if code := requestCode(t, s, sess.ID); code != http.StatusOK {
		t.Fatalf("requestCode: expected 200, got %d", code)
	}
	if rr := submitCode(t, s, sess.ID, "123456"); rr.Code != http.StatusOK {
		t.Fatalf("submitCode: expected 200, got %d", rr.Code)
	}

	logs.Reset()
	store.armAfter(1, errors.New("session store is unavailable"))

	req := httptest.NewRequest(http.MethodPost, "/v1/verification/session/"+sess.ID+"/code", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	if strings.Contains(logs.String(), sess.ID) {
		t.Errorf("the session id was written to the log — it is a registration credential:\n%s",
			logs.String())
	}
	// The failure must still be reported, just without the credential.
	if !strings.Contains(logs.String(), "failed to reload verification session") {
		t.Errorf("the reload failure was not logged at all:\n%s", logs.String())
	}
}
