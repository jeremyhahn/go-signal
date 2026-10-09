package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// --------------------------------------------------------------------------
// stubSDKStore implements signal.Store for WebUIHandler tests.
// --------------------------------------------------------------------------

type stubSDKStore struct {
	creds    *signal.Credentials
	credsErr error
	contacts []signal.Contact
	contErr  error
	messages []signal.Message
	msgsErr  error
}

func (s *stubSDKStore) GetCredentials(context.Context) (*signal.Credentials, error) {
	return s.creds, s.credsErr
}

func (s *stubSDKStore) SaveCredentials(_ context.Context, _ *signal.Credentials) error { return nil }

func (s *stubSDKStore) GetContacts() ([]signal.Contact, error) {
	return s.contacts, s.contErr
}

func (s *stubSDKStore) SaveContact(_ *signal.Contact) error { return nil }
func (s *stubSDKStore) DeleteContact(_ string) error        { return nil }
func (s *stubSDKStore) GetGroups() ([]signal.Group, error)  { return nil, nil }
func (s *stubSDKStore) SaveGroup(_ *signal.Group) error     { return nil }
func (s *stubSDKStore) GetStickerPacks() ([]signal.InstalledStickerPack, error) {
	return nil, nil
}
func (s *stubSDKStore) SaveStickerPack(_ *signal.InstalledStickerPack) error { return nil }
func (s *stubSDKStore) DeleteStickerPack(_ string) error                     { return nil }
func (s *stubSDKStore) Close() error                                         { return nil }

func (s *stubSDKStore) GetMessages(conversationID string, limit int) ([]signal.Message, error) {
	return s.messages, s.msgsErr
}

func (s *stubSDKStore) SaveMessage(_ *signal.Message) error { return nil }

// newWebUIClient creates a *signal.Client backed by the stub store, pointing
// at a dummy server URL. No real HTTP connections are made by these tests.
func newWebUIClient(t *testing.T, store signal.Store) *signal.Client {
	t.Helper()
	client, err := signal.NewClient(t.Context(), signal.ClientConfig{
		ServerURL: "http://127.0.0.1:0",
		DataDir:   t.TempDir(),
		UserAgent: "test-agent",
		Store:     store,
	})
	if err != nil {
		t.Fatalf("failed to create test SDK client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// newWebUIClientWithServer creates a *signal.Client pointing at srv.URL so
// that SDK HTTP calls reach the test server. Use this to exercise handlers
// that call client.WhoAmI, client.Register, etc.
func newWebUIClientWithServer(t *testing.T, srv *httptest.Server, store signal.Store) *signal.Client {
	t.Helper()
	client, err := signal.NewClient(t.Context(), signal.ClientConfig{
		ServerURL: srv.URL,
		DataDir:   t.TempDir(),
		UserAgent: "test-agent",
		Store:     store,
	})
	if err != nil {
		t.Fatalf("failed to create test SDK client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// --------------------------------------------------------------------------
// NewWebUIHandler + RegisterRoutes
// --------------------------------------------------------------------------

func TestNewWebUIHandler_NotNil(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)
	if h == nil {
		t.Fatal("NewWebUIHandler returned nil")
	}
}

func TestWebUIHandler_RegisterRoutes_NoPanic(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
}

// --------------------------------------------------------------------------
// handleIsRegistered
// --------------------------------------------------------------------------

func TestHandleIsRegistered_NotRegistered(t *testing.T) {
	// An unregistered client is a store holding no credentials (nil, nil),
	// the shape the real stores report; a load error fails NewClient.
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/account/registered", nil)
	rr := httptest.NewRecorder()
	h.handleIsRegistered(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	// Body should be "false\n"
	if !strings.Contains(rr.Body.String(), "false") {
		t.Errorf("expected false in body, got %q", rr.Body.String())
	}
}

func TestHandleIsRegistered_Registered(t *testing.T) {
	store := &stubSDKStore{
		creds: &signal.Credentials{UUID: "some-uuid", Number: "+15551234567"},
	}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/account/registered", nil)
	rr := httptest.NewRecorder()
	h.handleIsRegistered(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "true") {
		t.Errorf("expected true in body, got %q", rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetMessages
// --------------------------------------------------------------------------

func TestHandleGetMessages_MissingConversationID(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/messages", nil)
	rr := httptest.NewRecorder()
	h.handleGetMessages(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGetMessages_Success(t *testing.T) {
	store := &stubSDKStore{
		messages: []signal.Message{{Timestamp: 1000, Body: "hello"}},
	}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/messages?conversationId=conv-1", nil)
	rr := httptest.NewRecorder()
	h.handleGetMessages(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetMessages_StoreError(t *testing.T) {
	store := &stubSDKStore{msgsErr: errors.New("db error")}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/messages?conversationId=conv-1", nil)
	rr := httptest.NewRecorder()
	h.handleGetMessages(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

func TestHandleGetMessages_CustomLimit(t *testing.T) {
	store := &stubSDKStore{messages: []signal.Message{{Timestamp: 999, Body: "x"}}}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/messages?conversationId=conv-1&limit=5", nil)
	rr := httptest.NewRecorder()
	h.handleGetMessages(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleGetMessages_InvalidLimit(t *testing.T) {
	// Invalid limit string → ignored; falls back to default of 50.
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/messages?conversationId=conv-1&limit=abc", nil)
	rr := httptest.NewRecorder()
	h.handleGetMessages(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (default limit), got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleListContacts
// --------------------------------------------------------------------------

func TestHandleListContacts_Success(t *testing.T) {
	store := &stubSDKStore{
		contacts: []signal.Contact{{Name: "Alice", Number: "+15550001111"}},
	}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/contacts", nil)
	rr := httptest.NewRecorder()
	h.handleListContacts(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleListContacts_StoreError(t *testing.T) {
	store := &stubSDKStore{contErr: errors.New("store error")}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/contacts", nil)
	rr := httptest.NewRecorder()
	h.handleListContacts(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetConversations
// --------------------------------------------------------------------------

func TestHandleGetConversations_NonDAOStore(t *testing.T) {
	// stubSDKStore is not a *DAOStore, so the handler writes an empty JSON array.
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/conversations", nil)
	rr := httptest.NewRecorder()
	h.handleGetConversations(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// Response should be an empty JSON array.
	if !strings.Contains(rr.Body.String(), "[]") {
		t.Errorf("expected empty array, got %q", rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleCreateVerificationSession – bad JSON body
// --------------------------------------------------------------------------

func TestHandleCreateVerificationSession_InvalidJSON(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/verify/session", strings.NewReader("{bad json}"))
	rr := httptest.NewRecorder()
	h.handleCreateVerificationSession(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleRequestVerificationCode – bad JSON body
// --------------------------------------------------------------------------

func TestHandleRequestVerificationCode_InvalidJSON(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/verify/code", strings.NewReader("{bad json}"))
	rr := httptest.NewRecorder()
	h.handleRequestVerificationCode(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleSubmitVerificationCode – bad JSON body
// --------------------------------------------------------------------------

func TestHandleSubmitVerificationCode_InvalidJSON(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/verify/submit", strings.NewReader("{bad json}"))
	rr := httptest.NewRecorder()
	h.handleSubmitVerificationCode(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleRegister – bad JSON body
// --------------------------------------------------------------------------

func TestHandleRegister_InvalidJSON(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/register", strings.NewReader("{bad json}"))
	rr := httptest.NewRecorder()
	h.handleRegister(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleSendMessage – bad JSON body
// --------------------------------------------------------------------------

func TestHandleSendMessage_WebUI_InvalidJSON(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/messages/send", strings.NewReader("{bad json}"))
	rr := httptest.NewRecorder()
	h.handleSendMessage(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// relayCall – nil callSignaling service
// --------------------------------------------------------------------------

func TestWebUIRelayCall_NilSignalingService(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	// nil callSignaling service → 503
	h := NewWebUIHandler(client, nil)

	body := `{"callId":"c1","calleeUUID":"u2","callerUUID":"u1"}`
	for _, path := range []string{
		"/api/v1/call/offer",
		"/api/v1/call/answer",
		"/api/v1/call/ice",
		"/api/v1/call/hangup",
	} {
		var handler func(http.ResponseWriter, *http.Request)
		switch path {
		case "/api/v1/call/offer":
			handler = h.handleCallOfferRelay
		case "/api/v1/call/answer":
			handler = h.handleCallAnswerRelay
		case "/api/v1/call/ice":
			handler = h.handleCallICERelay
		case "/api/v1/call/hangup":
			handler = h.handleCallHangupRelay
		}

		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		rr := httptest.NewRecorder()
		handler(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: expected 503, got %d", path, rr.Code)
		}
	}
}

// --------------------------------------------------------------------------
// relayCall – invalid JSON body
// --------------------------------------------------------------------------

func TestWebUIRelayCall_InvalidJSON(t *testing.T) {
	store := &stubSDKStore{creds: &signal.Credentials{UUID: "some-uuid"}}
	client := newWebUIClient(t, store)
	stub := &stubCallSignalingService{}
	h := NewWebUIHandler(client, stub)

	for _, path := range []string{
		"/api/v1/call/offer",
		"/api/v1/call/answer",
		"/api/v1/call/ice",
		"/api/v1/call/hangup",
	} {
		var handler func(http.ResponseWriter, *http.Request)
		switch path {
		case "/api/v1/call/offer":
			handler = h.handleCallOfferRelay
		case "/api/v1/call/answer":
			handler = h.handleCallAnswerRelay
		case "/api/v1/call/ice":
			handler = h.handleCallICERelay
		case "/api/v1/call/hangup":
			handler = h.handleCallHangupRelay
		}

		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{bad json}"))
		rr := httptest.NewRecorder()
		handler(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", path, rr.Code)
		}
	}
}

// --------------------------------------------------------------------------
// relayCall – no credentials (unauthenticated)
// --------------------------------------------------------------------------

func TestWebUIRelayCall_NoCredentials(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	stub := &stubCallSignalingService{}
	h := NewWebUIHandler(client, stub)

	body := `{"callId":"c1","calleeUUID":"u2","callerUUID":"u1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/call/offer", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.handleCallOfferRelay(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// relayCall – success path (has credentials + stub relay works)
// --------------------------------------------------------------------------

func TestWebUIRelayCall_Success(t *testing.T) {
	store := &stubSDKStore{creds: &signal.Credentials{UUID: "caller-uuid"}}
	client := newWebUIClient(t, store)
	stub := &stubCallSignalingService{} // all relay methods return nil
	h := NewWebUIHandler(client, stub)

	body := `{"callId":"c1","calleeUUID":"callee-uuid","callerUUID":"caller-uuid"}`
	for _, tc := range []struct {
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"/api/v1/call/offer", h.handleCallOfferRelay},
		{"/api/v1/call/answer", h.handleCallAnswerRelay},
		{"/api/v1/call/ice", h.handleCallICERelay},
		{"/api/v1/call/hangup", h.handleCallHangupRelay},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(body))
		rr := httptest.NewRecorder()
		tc.handler(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Errorf("%s: expected 204, got %d: %s", tc.path, rr.Code, rr.Body.String())
		}
	}
}

// TestWebUIRelayCall_RelayError covers the fn() error branch in relayCall.
func TestWebUIRelayCall_RelayError(t *testing.T) {
	store := &stubSDKStore{creds: &signal.Credentials{UUID: "caller-uuid"}}
	client := newWebUIClient(t, store)
	stub := &stubCallSignalingService{offerErr: errors.New("relay failed")}
	h := NewWebUIHandler(client, stub)

	body := `{"callId":"c1","calleeUUID":"callee-uuid","callerUUID":"caller-uuid"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/call/offer", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.handleCallOfferRelay(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on relay error, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// writeJSON / writeError / ctx / readJSON helpers (via handleIsRegistered)
// --------------------------------------------------------------------------

func TestWebUIHandler_WriteJSON(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)
	rr := httptest.NewRecorder()
	h.writeJSON(rr, map[string]string{"k": "v"})
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json content type")
	}
}

func TestWebUIHandler_WriteError(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)
	rr := httptest.NewRecorder()
	h.writeError(rr, http.StatusBadRequest, "test error")
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestWebUIHandler_Ctx(t *testing.T) {
	store := &stubSDKStore{}
	client := newWebUIClient(t, store)
	h := NewWebUIHandler(client, nil)
	ctx, cancel := h.ctx()
	defer cancel()
	if ctx == nil {
		t.Error("expected non-nil context")
	}
}

// --------------------------------------------------------------------------
// handleWhoAmI – via mock SDK server
// --------------------------------------------------------------------------

func TestWebUIHandleWhoAmI_Success(t *testing.T) {
	// Set up a mock Signal server endpoint the SDK client will call.
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/accounts/whoami" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"uuid":   "some-uuid",
				"number": "+15551234567",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockSrv.Close()

	store := &stubSDKStore{}
	client := newWebUIClientWithServer(t, mockSrv, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/account/whoami", nil)
	rr := httptest.NewRecorder()
	h.handleWhoAmI(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestWebUIHandleWhoAmI_Error(t *testing.T) {
	// Mock server returns an error.
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer mockSrv.Close()

	store := &stubSDKStore{}
	client := newWebUIClientWithServer(t, mockSrv, store)
	h := NewWebUIHandler(client, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/account/whoami", nil)
	rr := httptest.NewRecorder()
	h.handleWhoAmI(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleCreateVerificationSession – success/error via mock SDK server
// --------------------------------------------------------------------------

func TestHandleCreateVerificationSession_SDKError(t *testing.T) {
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer mockSrv.Close()

	store := &stubSDKStore{}
	client := newWebUIClientWithServer(t, mockSrv, store)
	h := NewWebUIHandler(client, nil)

	body := `{"number":"+15551234567"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/verify/session", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.handleCreateVerificationSession(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleRequestVerificationCode – success/error via mock SDK server
// --------------------------------------------------------------------------

func TestHandleRequestVerificationCode_SDKError(t *testing.T) {
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer mockSrv.Close()

	store := &stubSDKStore{}
	client := newWebUIClientWithServer(t, mockSrv, store)
	h := NewWebUIHandler(client, nil)

	body := `{"sessionId":"sess-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/verify/code", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.handleRequestVerificationCode(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleSubmitVerificationCode – error via mock SDK server
// --------------------------------------------------------------------------

func TestHandleSubmitVerificationCode_SDKError(t *testing.T) {
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer mockSrv.Close()

	store := &stubSDKStore{}
	client := newWebUIClientWithServer(t, mockSrv, store)
	h := NewWebUIHandler(client, nil)

	body := `{"sessionId":"sess-1","code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/verify/submit", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.handleSubmitVerificationCode(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleRegister – error via mock SDK server
// --------------------------------------------------------------------------

func TestHandleRegister_SDKError(t *testing.T) {
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer mockSrv.Close()

	store := &stubSDKStore{}
	client := newWebUIClientWithServer(t, mockSrv, store)
	h := NewWebUIHandler(client, nil)

	body := `{"number":"+15551234567","sessionId":"sess-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/account/register", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.handleRegister(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleSendMessage – error via mock SDK server
// --------------------------------------------------------------------------

func TestHandleSendMessage_WebUI_SDKError(t *testing.T) {
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer mockSrv.Close()

	store := &stubSDKStore{}
	client := newWebUIClientWithServer(t, mockSrv, store)
	h := NewWebUIHandler(client, nil)

	body := `{"recipient":"+15550001111","text":"hello"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/messages/send", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.handleSendMessage(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// WebUIEventHub
// --------------------------------------------------------------------------

func TestWebUIEventHub_SetAllowedOrigins_Empty(t *testing.T) {
	h := NewWebUIEventHub()
	// With no origins, acceptOptions should return default (empty patterns).
	opts := h.acceptOptions()
	if opts == nil {
		t.Fatal("expected non-nil AcceptOptions")
	}
	if len(opts.OriginPatterns) != 0 {
		t.Errorf("expected no origin patterns, got %v", opts.OriginPatterns)
	}
}

func TestWebUIEventHub_SetAllowedOrigins_NonEmpty(t *testing.T) {
	h := NewWebUIEventHub()
	origins := []string{"https://example.com", "https://app.example.com"}
	h.SetAllowedOrigins(origins)

	opts := h.acceptOptions()
	if opts == nil {
		t.Fatal("expected non-nil AcceptOptions")
	}
	if len(opts.OriginPatterns) != 2 {
		t.Fatalf("expected 2 origin patterns, got %d", len(opts.OriginPatterns))
	}
	if opts.OriginPatterns[0] != origins[0] {
		t.Errorf("expected %q, got %q", origins[0], opts.OriginPatterns[0])
	}
	if opts.OriginPatterns[1] != origins[1] {
		t.Errorf("expected %q, got %q", origins[1], opts.OriginPatterns[1])
	}
}

func TestWebUIEventHub_SetAllowedOrigins_Override(t *testing.T) {
	h := NewWebUIEventHub()
	h.SetAllowedOrigins([]string{"https://old.example.com"})
	h.SetAllowedOrigins([]string{"https://new.example.com"})

	opts := h.acceptOptions()
	if len(opts.OriginPatterns) != 1 || opts.OriginPatterns[0] != "https://new.example.com" {
		t.Errorf("expected overridden origins, got %v", opts.OriginPatterns)
	}
}

func TestWebUIEventHub_Broadcast_NoClients_SecondCall(t *testing.T) {
	h := NewWebUIEventHub()
	// Broadcast with no clients must not panic (second call after SetAllowedOrigins).
	h.SetAllowedOrigins(nil)
	h.Broadcast("test-event", map[string]string{"key": "value"})
}
