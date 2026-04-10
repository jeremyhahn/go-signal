package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// --------------------------------------------------------------------------
// handleWebSocket
// --------------------------------------------------------------------------

func TestHandleWebSocket_NoWSHandler(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleWebSocket_NoWSHandler_CheckBody(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Body.Len() == 0 {
		t.Error("expected error body")
	}
}

// --------------------------------------------------------------------------
// handleWebSocketProvisioning
// --------------------------------------------------------------------------

func TestHandleWebSocketProvisioning_NoWSHandler(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/provisioning", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleWebSocketProvisioning_NoWSHandler_CheckBody(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/provisioning", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Body.Len() == 0 {
		t.Error("expected error body")
	}
}
