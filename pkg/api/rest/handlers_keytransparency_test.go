package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// handleKeyTransparencySearch
// --------------------------------------------------------------------------

func TestHandleKeyTransparencySearch_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"token":"dGVzdC10b2tlbg=="}`
	req := httptest.NewRequest(http.MethodPost, "/v1/key-transparency/search", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleKeyTransparencySearch_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/key-transparency/search", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleKeyTransparencySearch_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	body := `{"token":"dGVzdC10b2tlbg=="}`
	req := httptest.NewRequest(http.MethodPost, "/v1/key-transparency/search", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleKeyTransparencyMonitor
// --------------------------------------------------------------------------

func TestHandleKeyTransparencyMonitor_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"token":"dGVzdC10b2tlbg=="}`
	req := httptest.NewRequest(http.MethodPost, "/v1/key-transparency/monitor", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleKeyTransparencyMonitor_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/key-transparency/monitor", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleKeyTransparencyMonitor_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	body := `{"token":"dGVzdC10b2tlbg=="}`
	req := httptest.NewRequest(http.MethodPost, "/v1/key-transparency/monitor", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetDistinguishedKey
// --------------------------------------------------------------------------

func TestHandleGetDistinguishedKey_Success(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/key-transparency/distinguished", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
}

func TestHandleGetDistinguishedKey_NoAuthRequired(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/key-transparency/distinguished", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 without auth, got %d", rr.Code)
	}
}
