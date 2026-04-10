package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/verification"
)

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
// caller-provided verification.Manager instead of the default one. This allows
// tests to inject custom TTLs, session limits, and cleanup intervals.
func newTestServerWithCustomVerification(t *testing.T, mgr *verification.Manager) *Server {
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
	verificationMgr := verification.NewManager(store, transport, verification.ManagerConfig{
		CodeLength:  6,
		CodeTTL:     5 * time.Minute,
		MaxAttempts: 3,
		MaxSessions: 2, // cap at 2 so the test runs fast
		SessionTTL:  10 * time.Minute,
	})
	t.Cleanup(verificationMgr.Shutdown)

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
	verificationMgr := verification.NewManager(store, transport, verification.ManagerConfig{
		CodeLength:  6,
		CodeTTL:     5 * time.Minute,
		MaxAttempts: 3,
		SessionTTL:  time.Nanosecond,
	})
	t.Cleanup(verificationMgr.Shutdown)

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
	verificationMgr := verification.NewManager(store, transport, verification.ManagerConfig{
		CodeLength:  6,
		CodeTTL:     5 * time.Minute,
		MaxAttempts: 3,
		SessionTTL:  time.Nanosecond,
	})
	t.Cleanup(verificationMgr.Shutdown)

	s := newTestServerWithCustomVerification(t, verificationMgr)
	sess := createSession(t, s, "+15551234567")

	time.Sleep(5 * time.Millisecond)

	statusCode := requestCode(t, s, sess.ID)
	if statusCode != http.StatusGone {
		t.Errorf("expected 410 Gone, got %d", statusCode)
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
	verificationMgr := verification.NewManager(store, transport, verification.ManagerConfig{
		CodeLength:  6,
		CodeTTL:     time.Nanosecond,
		MaxAttempts: 3,
		SessionTTL:  time.Nanosecond,
	})
	t.Cleanup(verificationMgr.Shutdown)

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
	verificationMgr := verification.NewManager(store, transport, verification.ManagerConfig{
		CodeLength:  6,
		CodeTTL:     5 * time.Minute,
		MaxAttempts: 1, // allow only one attempt
		SessionTTL:  10 * time.Minute,
	})
	t.Cleanup(verificationMgr.Shutdown)

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
	verificationMgr := verification.NewManager(store, transport, verification.ManagerConfig{
		CodeLength:      6,
		CodeTTL:         time.Nanosecond,
		MaxAttempts:     3,
		SessionTTL:      time.Nanosecond,
		CleanupInterval: 10 * time.Millisecond, // fast cleanup for tests
	})
	t.Cleanup(verificationMgr.Shutdown)

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
	verificationMgr := verification.NewManager(store, transport, verification.ManagerConfig{
		CodeLength:  6,
		CodeTTL:     time.Nanosecond,
		MaxAttempts: 3,
		SessionTTL:  time.Nanosecond,
	})
	t.Cleanup(verificationMgr.Shutdown)

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
