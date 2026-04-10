package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --------------------------------------------------------------------------
// handleGetConfig
// --------------------------------------------------------------------------

func TestHandleGetConfig_Success(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	config, ok := resp["config"]
	if !ok {
		t.Error("expected 'config' key in response")
	}
	arr, ok := config.([]any)
	if !ok {
		t.Fatal("expected config to be an array")
	}
	if len(arr) != 0 {
		t.Errorf("expected empty config array, got %d elements", len(arr))
	}
}

func TestHandleGetConfig_NoAuthRequired(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Should succeed without authentication.
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetRemoteConfig
// --------------------------------------------------------------------------

func TestHandleGetRemoteConfig_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/config", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp RemoteConfigResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Config) == 0 {
		t.Error("expected non-empty config list")
	}

	// Verify known config items.
	found := false
	for _, item := range resp.Config {
		if item.Name == "global.calling" && item.Enabled {
			found = true
		}
	}
	if !found {
		t.Error("expected global.calling config item")
	}
}

func TestHandleGetRemoteConfig_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/config", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}
