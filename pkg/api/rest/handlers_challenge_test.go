package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/captcha"
)

// --------------------------------------------------------------------------
// handleChallengeResponse
// --------------------------------------------------------------------------

func TestHandleChallengeResponse_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"type":"captcha","token":"test-token","captcha":"test-captcha-valid"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/challenge", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleChallengeResponse_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/challenge", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleChallengeResponse_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/challenge", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleRequestPushChallenge
// --------------------------------------------------------------------------

func TestHandleRequestPushChallenge_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge/push", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRequestPushChallenge_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/challenge/push", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestHandleChallengeResponse_NoProviderConfigured asserts the fail-closed
// path: a server with no captcha backend refuses the submission with 503
// rather than dereferencing a nil verifier. A panic here reaches the client
// as a dropped connection, which is what run 4336 saw.
func TestHandleChallengeResponse_NoProviderConfigured(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	s.captcha = captcha.NewCaptchaManagerWithConfig(captcha.CaptchaManagerConfig{
		Logger: s.logger,
	})

	body := `{"type":"captcha","token":"test-token","captcha":"test-captcha-valid"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/challenge", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

// A push challenge needs no captcha backend, so it must still succeed on a
// server with none configured.
func TestHandleChallengeResponse_PushWithNoProviderConfigured(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	s.captcha = captcha.NewCaptchaManagerWithConfig(captcha.CaptchaManagerConfig{
		Logger: s.logger,
	})

	body := `{"type":"rateLimitPushChallenge","token":"test-push-token"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/challenge", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}
