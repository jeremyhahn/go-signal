package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/calling"
)

// stubCallSignalingService satisfies service.CallSignalingService and lets
// tests control which error (if any) each relay method returns.
type stubCallSignalingService struct {
	offerErr  error
	answerErr error
	iceErr    error
	hangupErr error
}

func (s *stubCallSignalingService) RelayOffer(_ context.Context, _ string, _ *calling.CallSignalMessage) error {
	return s.offerErr
}

func (s *stubCallSignalingService) RelayAnswer(_ context.Context, _ string, _ *calling.CallSignalMessage) error {
	return s.answerErr
}

func (s *stubCallSignalingService) RelayICECandidate(_ context.Context, _ string, _ *calling.CallSignalMessage) error {
	return s.iceErr
}

func (s *stubCallSignalingService) RelayHangup(_ context.Context, _ string, _ *calling.CallSignalMessage) error {
	return s.hangupErr
}

func (s *stubCallSignalingService) GetTURNCredentials(_ context.Context) (*calling.GetCallingRelaysResponse, error) {
	return &calling.GetCallingRelaysResponse{}, nil
}

// makeCallSignalingServer creates a server with a stub call signaling service
// and a pre-populated test account.
func makeCallSignalingServer(t *testing.T, svc *stubCallSignalingService) *Server {
	t.Helper()
	s, _ := newTestServerWithAccount(t)
	s.callSignaling = svc
	return s
}

// injectAccountContext returns an http.Request with the test account injected
// directly into its context, bypassing Basic Auth middleware.
func injectAccountContext(r *http.Request, acct *accounts.Account) *http.Request {
	return r.WithContext(contextWithAccount(r.Context(), acct))
}

// validCallBody is a minimal JSON call signal payload.
const validCallBody = `{"callId":"call-1","calleeUUID":"callee-uuid","callerUUID":"caller-uuid","type":"offer"}`

// --------------------------------------------------------------------------
// relayCallSignal – shared helper, exercised via each public handler
// --------------------------------------------------------------------------

func TestRelayCallSignal_Unauthenticated(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{})

	// Request without an account in context triggers the 401 branch.
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(validCallBody))
	rr := httptest.NewRecorder()
	s.handleCallOffer(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without account, got %d", rr.Code)
	}
}

func TestRelayCallSignal_InvalidJSON(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{bad json}"))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallOffer(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleCallOffer
// --------------------------------------------------------------------------

func TestHandleCallOffer_Success(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/v1/call/offer", strings.NewReader(validCallBody))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallOffer(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCallOffer_PeerNotConnected(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{
		offerErr: &calling.PeerNotConnectedError{UUID: "callee-uuid"},
	})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/v1/call/offer", strings.NewReader(validCallBody))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallOffer(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for peer not connected, got %d", rr.Code)
	}
}

func TestHandleCallOffer_InvalidCallSignal(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{
		offerErr: &calling.InvalidCallSignalError{Message: "bad offer"},
	})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/v1/call/offer", strings.NewReader(validCallBody))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallOffer(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid call signal, got %d", rr.Code)
	}
}

func TestHandleCallOffer_InternalError(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{
		offerErr: &accounts.InvalidArgumentError{Field: "test", Message: "unexpected"},
	})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/v1/call/offer", strings.NewReader(validCallBody))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallOffer(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for internal error, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleCallAnswer
// --------------------------------------------------------------------------

func TestHandleCallAnswer_Success(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{})
	acct := testAccount()

	body := `{"callId":"call-1","calleeUUID":"callee-uuid","callerUUID":"caller-uuid","type":"answer"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/call/answer", strings.NewReader(body))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallAnswer(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCallAnswer_PeerNotConnected(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{
		answerErr: &calling.PeerNotConnectedError{UUID: "caller-uuid"},
	})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/v1/call/answer", strings.NewReader(validCallBody))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallAnswer(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleCallAnswer_Unauthenticated(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{})

	req := httptest.NewRequest(http.MethodPost, "/v1/call/answer", strings.NewReader(validCallBody))
	rr := httptest.NewRecorder()
	s.handleCallAnswer(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleCallICE
// --------------------------------------------------------------------------

func TestHandleCallICE_Success(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{})
	acct := testAccount()

	body := `{"callId":"call-1","calleeUUID":"callee-uuid","callerUUID":"caller-uuid","type":"ice","candidates":["candidate:0 1 UDP 2113667327 192.0.2.1 54400 typ host"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/call/ice", strings.NewReader(body))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallICE(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCallICE_PeerNotConnected(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{
		iceErr: &calling.PeerNotConnectedError{UUID: "callee-uuid"},
	})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/v1/call/ice", strings.NewReader(validCallBody))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallICE(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleCallICE_Unauthenticated(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{})

	req := httptest.NewRequest(http.MethodPost, "/v1/call/ice", strings.NewReader(validCallBody))
	rr := httptest.NewRecorder()
	s.handleCallICE(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleCallHangup
// --------------------------------------------------------------------------

func TestHandleCallHangup_Success(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{})
	acct := testAccount()

	body := `{"callId":"call-1","calleeUUID":"callee-uuid","callerUUID":"caller-uuid","type":"hangup"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/call/hangup", strings.NewReader(body))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallHangup(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCallHangup_PeerNotConnected(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{
		hangupErr: &calling.PeerNotConnectedError{UUID: "caller-uuid"},
	})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/v1/call/hangup", strings.NewReader(validCallBody))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallHangup(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleCallHangup_InvalidJSON(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/v1/call/hangup", strings.NewReader("{bad json}"))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallHangup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleCallHangup_Unauthenticated(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{})

	req := httptest.NewRequest(http.MethodPost, "/v1/call/hangup", strings.NewReader(validCallBody))
	rr := httptest.NewRecorder()
	s.handleCallHangup(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// relayCallSignal – InvalidCallSignalError and unknown error for all handlers
// --------------------------------------------------------------------------

func TestHandleCallAnswer_InvalidCallSignal(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{
		answerErr: &calling.InvalidCallSignalError{Message: "bad sdp"},
	})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/v1/call/answer", strings.NewReader(validCallBody))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallAnswer(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleCallICE_InternalError(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{
		iceErr: &accounts.InvalidArgumentError{Field: "test", Message: "unexpected"},
	})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/v1/call/ice", strings.NewReader(validCallBody))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallICE(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestHandleCallHangup_InternalError(t *testing.T) {
	s := makeCallSignalingServer(t, &stubCallSignalingService{
		hangupErr: &accounts.InvalidArgumentError{Field: "test", Message: "unexpected"},
	})
	acct := testAccount()

	req := httptest.NewRequest(http.MethodPost, "/v1/call/hangup", strings.NewReader(validCallBody))
	req = injectAccountContext(req, acct)
	rr := httptest.NewRecorder()
	s.handleCallHangup(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}
