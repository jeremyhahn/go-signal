package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --------------------------------------------------------------------------
// handleDeviceCheckAttestChallenge
// --------------------------------------------------------------------------

func TestHandleDeviceCheckAttestChallenge_Success(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/devicecheck/attest", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp["challenge"] == "" {
		t.Error("expected non-empty challenge")
	}
}

func TestHandleDeviceCheckAttestChallenge_NoAuthRequired(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/devicecheck/attest", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleDeviceCheckAttest
// --------------------------------------------------------------------------

func TestHandleDeviceCheckAttest_NotImplemented(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/devicecheck/attest", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rr.Code)
	}
}

func TestHandleDeviceCheckAttest_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/devicecheck/attest", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleDeviceCheckAssertChallenge
// --------------------------------------------------------------------------

func TestHandleDeviceCheckAssertChallenge_Success(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/devicecheck/assert", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp["challenge"] == "" {
		t.Error("expected non-empty challenge")
	}
}

func TestHandleDeviceCheckAssertChallenge_NoAuthRequired(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/devicecheck/assert", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleDeviceCheckAssert
// --------------------------------------------------------------------------

func TestHandleDeviceCheckAssert_NotImplemented(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/devicecheck/assert", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rr.Code)
	}
}

func TestHandleDeviceCheckAssert_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/devicecheck/assert", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// generateChallenge
// --------------------------------------------------------------------------

func TestGenerateChallenge_ReturnsNonEmpty(t *testing.T) {
	c, err := generateChallenge()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == "" {
		t.Error("expected non-empty challenge")
	}
}

func TestGenerateChallenge_UniqueValues(t *testing.T) {
	c1, _ := generateChallenge()
	c2, _ := generateChallenge()
	if c1 == c2 {
		t.Error("expected unique challenges")
	}
}
