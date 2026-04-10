package rest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// handleSendProvisioningMessage
// --------------------------------------------------------------------------

func TestHandleSendProvisioningMessage_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"body":"provisioning-message-body"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/provisioning/dest-uuid", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Without WS sessions, delivery silently skips.
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSendProvisioningMessage_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/provisioning/dest-uuid", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSendProvisioningMessage_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	body := `{"body":"test"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/provisioning/dest-uuid", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Provisioning now requires authentication (H1 fix).
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}
