package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/limits"
)

// --------------------------------------------------------------------------
// handleWhoAmI
// --------------------------------------------------------------------------

func TestHandleWhoAmI_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/whoami", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp WhoAmIResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.UUID != testAccountUUID {
		t.Errorf("expected UUID %s, got %s", testAccountUUID, resp.UUID)
	}
	if resp.Number != testAccountNumber {
		t.Errorf("expected Number %s, got %s", testAccountNumber, resp.Number)
	}
	if resp.PNI == "" {
		t.Error("expected non-empty PNI")
	}
}

func TestHandleWhoAmI_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/whoami", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleSetAccountAttributes
// --------------------------------------------------------------------------

func TestHandleSetAccountAttributes_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"fetchesMessages":true,"registrationId":99999,"name":"Updated","capabilities":{"storage":true}}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/attributes/", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSetAccountAttributes_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/attributes/", strings.NewReader("not json"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSetAccountAttributes_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	body := `{"fetchesMessages":true}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/attributes/", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleSetAccountAttributes_InvalidUAKBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"unidentifiedAccessKey":"!!!not-base64!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/attributes/", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleAccountExists
// --------------------------------------------------------------------------

func TestHandleAccountExists_Found(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodHead, "/v1/accounts/account/"+testAccountUUID, nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleAccountExists_NotFound(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodHead, "/v1/accounts/account/nonexistent-uuid", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleAccountExists_ByNumber(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodHead, "/v1/accounts/account/"+testAccountNumber, nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleAccountExists_AcceptsAuthenticatedRequests(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Authenticated requests are accepted — the endpoint works for both
	// authenticated and unauthenticated callers, matching Signal-cli behavior.
	req := httptest.NewRequest(http.MethodHead, "/v1/accounts/account/"+testAccountUUID, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for authenticated request, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleAccountExists – rate limiting
// --------------------------------------------------------------------------

func TestHandleAccountExists_RateLimit_AllowsUnderLimit(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	// Default server has no rate limiter — all requests go through.
	for range 5 {
		req := httptest.NewRequest(http.MethodHead, "/v1/accounts/account/"+testAccountUUID, nil)
		req.RemoteAddr = "10.0.0.1:12345"
		rr := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
	}
}

func TestHandleAccountExists_RateLimit_Returns429WhenExceeded(t *testing.T) {
	// Create a fresh server then manually wire a tiny rate limiter.
	s := newTestServer(t)

	// Create account so the first N requests succeed with 200.
	acct := testAccount()
	if err := s.accounts.Create(t.Context(), acct); err != nil {
		t.Fatalf("create account: %v", err)
	}

	// Install a registry with a very tight AccountCheck bucket (size=2).
	reg := limits.NewRegistry(limits.Config{
		Registration:   limits.BucketConfig{BucketSize: 6, RefillRate: 0.2},
		Messages:       limits.BucketConfig{BucketSize: 60, RefillRate: 60},
		PreKeys:        limits.BucketConfig{BucketSize: 6, RefillRate: 0.01},
		Profiles:       limits.BucketConfig{BucketSize: 4320, RefillRate: 216},
		Attachments:    limits.BucketConfig{BucketSize: 50, RefillRate: 41.67},
		Verification:   limits.BucketConfig{BucketSize: 6, RefillRate: 0.2},
		PIN:            limits.BucketConfig{BucketSize: 10, RefillRate: 0.000116},
		Usernames:      limits.BucketConfig{BucketSize: 100, RefillRate: 1.67},
		Authentication: limits.BucketConfig{BucketSize: 10, RefillRate: 0.167},
		AccountCheck:   limits.BucketConfig{BucketSize: 2, RefillRate: 0.0001},
	})
	s.rateLimits = reg

	mux := http.NewServeMux()
	s.routes(mux)
	s.httpServer.Handler = securityHeadersMiddleware(
		bodyLimitMiddleware(
			jsonMiddleware(
				loggingMiddleware(s.logger, mux),
			),
		),
	)

	ip := "10.0.0.2:1234"

	// Exhaust the 2-token bucket.
	for range 2 {
		req := httptest.NewRequest(http.MethodHead, "/v1/accounts/account/"+testAccountUUID, nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200 while under limit, got %d", rr.Code)
		}
	}

	// This request should now be rate-limited.
	req := httptest.NewRequest(http.MethodHead, "/v1/accounts/account/"+testAccountUUID, nil)
	req.RemoteAddr = ip
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after limit exceeded, got %d", rr.Code)
	}
}

func TestHandleAccountExists_RateLimit_DifferentIPsAreIndependent(t *testing.T) {
	s := newTestServer(t)

	acct := testAccount()
	if err := s.accounts.Create(t.Context(), acct); err != nil {
		t.Fatalf("create account: %v", err)
	}

	reg := limits.NewRegistry(limits.Config{
		Registration:   limits.BucketConfig{BucketSize: 6, RefillRate: 0.2},
		Messages:       limits.BucketConfig{BucketSize: 60, RefillRate: 60},
		PreKeys:        limits.BucketConfig{BucketSize: 6, RefillRate: 0.01},
		Profiles:       limits.BucketConfig{BucketSize: 4320, RefillRate: 216},
		Attachments:    limits.BucketConfig{BucketSize: 50, RefillRate: 41.67},
		Verification:   limits.BucketConfig{BucketSize: 6, RefillRate: 0.2},
		PIN:            limits.BucketConfig{BucketSize: 10, RefillRate: 0.000116},
		Usernames:      limits.BucketConfig{BucketSize: 100, RefillRate: 1.67},
		Authentication: limits.BucketConfig{BucketSize: 10, RefillRate: 0.167},
		AccountCheck:   limits.BucketConfig{BucketSize: 1, RefillRate: 0.0001},
	})
	s.rateLimits = reg

	mux := http.NewServeMux()
	s.routes(mux)
	s.httpServer.Handler = securityHeadersMiddleware(
		bodyLimitMiddleware(
			jsonMiddleware(
				loggingMiddleware(s.logger, mux),
			),
		),
	)

	// Exhaust IP "192.0.2.1" (bucket size = 1).
	req1 := httptest.NewRequest(http.MethodHead, "/v1/accounts/account/"+testAccountUUID, nil)
	req1.RemoteAddr = "192.0.2.1:1"
	s.httpServer.Handler.ServeHTTP(httptest.NewRecorder(), req1)

	// "192.0.2.1" should now be limited.
	req2 := httptest.NewRequest(http.MethodHead, "/v1/accounts/account/"+testAccountUUID, nil)
	req2.RemoteAddr = "192.0.2.1:1"
	rr2 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for exhausted IP, got %d", rr2.Code)
	}

	// Different IP "192.0.2.2" should still have its own fresh bucket.
	req3 := httptest.NewRequest(http.MethodHead, "/v1/accounts/account/"+testAccountUUID, nil)
	req3.RemoteAddr = "192.0.2.2:1"
	rr3 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Errorf("expected 200 for different IP, got %d", rr3.Code)
	}
}

// --------------------------------------------------------------------------
// handleDeleteAccount
// --------------------------------------------------------------------------

func TestHandleDeleteAccount_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/me", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleDeleteAccount_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/me", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleRegisterGcm / handleUnregisterGcm
// --------------------------------------------------------------------------

func TestHandleRegisterGcm_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"gcmRegistrationId":"test-gcm-token"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/gcm/", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegisterGcm_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/gcm/", strings.NewReader("not json"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleRegisterGcm_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	body := `{"gcmRegistrationId":"token"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/gcm/", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleUnregisterGcm_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/gcm/", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUnregisterGcm_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/gcm/", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleRegisterApn / handleUnregisterApn
// --------------------------------------------------------------------------

func TestHandleRegisterApn_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"apnRegistrationId":"apn-token","voipRegistrationId":"voip-token"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/apn/", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRegisterApn_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/apn/", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleRegisterApn_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	body := `{"apnRegistrationId":"apn-token"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/apn/", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleUnregisterApn_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/apn/", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleUnregisterApn_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/apn/", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}
