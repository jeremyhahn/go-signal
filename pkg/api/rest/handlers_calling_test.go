package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// handleGetCallingRelays
// --------------------------------------------------------------------------

func TestHandleGetCallingRelays_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/calling/relays", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetCallingRelays_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/calling/relays", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetCallLinkAuth
// --------------------------------------------------------------------------

func TestHandleGetCallLinkAuth_NoZKConfig(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Without callingZKParams configured, the endpoint returns 400.
	req := httptest.NewRequest(http.MethodPost, "/v1/call-link/create-auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without ZK config, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetCallLinkAuth_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/call-link/create-auth", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleGetCallLinkAuth_WithBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Without callingZKParams the endpoint returns 400 regardless of body.
	body := `{"createCallLinkCredentialRequest":"dGVzdA=="}`
	req := httptest.NewRequest(http.MethodPost, "/v1/call-link/create-auth", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without ZK config, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetCallLinkAuth – missing coverage
// --------------------------------------------------------------------------

func TestHandleGetCallLinkAuth_InvalidJSONBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/call-link/create-auth", strings.NewReader("{bad json}"))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON body, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleSubmitCallQualitySurvey
// --------------------------------------------------------------------------

func TestHandleSubmitCallQualitySurvey_AuthenticatedForbidden(t *testing.T) {
	// Java behavior: if authenticatedDevice.isPresent() -> 403 Forbidden.
	// Simulate this by injecting an account directly into the request context.
	s, _ := newTestServerWithAccount(t)
	acct := testAccount()

	body := `{
		"userSatisfied": true,
		"startTimestamp": 1710500000000,
		"endTimestamp": 1710500060000,
		"callType": "AUDIO_CALL",
		"success": true,
		"callEndReason": "CALLER_HUNG_UP"
	}`
	req := httptest.NewRequest(http.MethodPut, "/v1/call_quality_survey", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Inject the authenticated account into the context directly.
	ctx := contextWithAccount(req.Context(), acct)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	s.handleSubmitCallQualitySurvey(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for authenticated call quality survey, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSubmitCallQualitySurvey_Success(t *testing.T) {
	s := newTestServer(t)

	body := `{
		"userSatisfied": true,
		"startTimestamp": 1710500000000,
		"endTimestamp": 1710500060000,
		"callType": "AUDIO_CALL",
		"success": true,
		"callEndReason": "CALLER_HUNG_UP"
	}`
	req := httptest.NewRequest(http.MethodPut, "/v1/call_quality_survey", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSubmitCallQualitySurvey_MissingStartTimestamp(t *testing.T) {
	s := newTestServer(t)

	body := `{
		"userSatisfied": true,
		"endTimestamp": 1710500060000,
		"callType": "AUDIO_CALL",
		"success": true,
		"callEndReason": "CALLER_HUNG_UP"
	}`
	req := httptest.NewRequest(http.MethodPut, "/v1/call_quality_survey", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSubmitCallQualitySurvey_MissingCallType(t *testing.T) {
	s := newTestServer(t)

	body := `{
		"userSatisfied": true,
		"startTimestamp": 1710500000000,
		"endTimestamp": 1710500060000,
		"success": true,
		"callEndReason": "CALLER_HUNG_UP"
	}`
	req := httptest.NewRequest(http.MethodPut, "/v1/call_quality_survey", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSubmitCallQualitySurvey_InvalidBody(t *testing.T) {
	s := newTestServer(t)

	body := `{not valid json`
	req := httptest.NewRequest(http.MethodPut, "/v1/call_quality_survey", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSubmitCallQualitySurvey_EmptyBody(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/call_quality_survey", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}
