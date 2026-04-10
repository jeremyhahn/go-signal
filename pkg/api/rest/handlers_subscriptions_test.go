package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// --------------------------------------------------------------------------
// handleGetSubscriptionConfig
// --------------------------------------------------------------------------

func TestHandleGetSubscriptionConfig_NotImplemented(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/subscription/configuration", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetSubscriptionConfig_NoAuthRequired(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/subscription/configuration", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// No authentication header required — endpoint is publicly accessible.
	// The handler returns 501 regardless of auth state.
	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501 without auth, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleUpdateSubscriber
// --------------------------------------------------------------------------

func TestHandleUpdateSubscriber_NotImplemented(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/subscription/sub123", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rr.Code)
	}
}

func TestHandleUpdateSubscriber_NoAuthRequired(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/subscription/sub123", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501 without auth, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetSubscription
// --------------------------------------------------------------------------

func TestHandleGetSubscription_NotImplemented(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/subscription/sub123", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetSubscription_NoAuthRequired(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/subscription/sub456", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501 without auth, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleDeleteSubscriber
// --------------------------------------------------------------------------

func TestHandleDeleteSubscriber_NotImplemented(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/subscription/sub123", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rr.Code)
	}
}

func TestHandleDeleteSubscriber_NoAuthRequired(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/subscription/sub456", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501 without auth, got %d", rr.Code)
	}
}
