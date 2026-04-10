package websocket

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	ws "github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/auth"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
	wsproto "github.com/jeremyhahn/go-signal/pkg/websocket/wsproto"
)

func handlerTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// wsWrite serialises msg as a protobuf binary WebSocket frame and sends it
// over conn. Signal sessions are configured with FrameFormatProtobuf so tests
// must speak the same wire format.
func wsWrite(t *testing.T, conn *ws.Conn, msg *signalws.WebSocketMessage) {
	t.Helper()
	data, err := signalws.MarshalFrame(msg, signalws.FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("wsWrite: MarshalFrame: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, ws.MessageBinary, data); err != nil {
		t.Fatalf("wsWrite: conn.Write: %v", err)
	}
}

// wsRead receives a binary WebSocket frame and deserialises it as a protobuf
// WebSocketMessage. It mirrors the server's FrameFormatProtobuf encoding.
func wsRead(t *testing.T, conn *ws.Conn) *signalws.WebSocketMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("wsRead: conn.Read: %v", err)
	}
	msg, err := signalws.UnmarshalFrame(data, signalws.FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("wsRead: UnmarshalFrame: %v", err)
	}
	return msg
}

// stubAccountStore is a minimal AccountStore for testing.
type stubAccountStore struct {
	accounts map[string]*accounts.Account
}

func newStubAccountStore() *stubAccountStore {
	return &stubAccountStore{accounts: make(map[string]*accounts.Account)}
}

func (s *stubAccountStore) Create(_ context.Context, account *accounts.Account) error {
	s.accounts[account.UUID] = account
	return nil
}

func (s *stubAccountStore) Get(_ context.Context, uuid string) (*accounts.Account, error) {
	acct, ok := s.accounts[uuid]
	if !ok {
		return nil, &accounts.AccountNotFoundError{Identifier: uuid}
	}
	return acct, nil
}

func (s *stubAccountStore) GetByNumber(_ context.Context, number string) (*accounts.Account, error) {
	for _, acct := range s.accounts {
		if acct.Number == number {
			return acct, nil
		}
	}
	return nil, &accounts.AccountNotFoundError{}
}

func (s *stubAccountStore) Update(_ context.Context, account *accounts.Account) error {
	s.accounts[account.UUID] = account
	return nil
}

func (s *stubAccountStore) Delete(_ context.Context, uuid string) error {
	delete(s.accounts, uuid)
	return nil
}

// stubMessageStore is a minimal MessageStore for testing.
type stubMessageStore struct {
	messages map[string][]*messages.Envelope
}

func newStubMessageStore() *stubMessageStore {
	return &stubMessageStore{messages: make(map[string][]*messages.Envelope)}
}

func (s *stubMessageStore) Insert(_ context.Context, destUUID string, destDevice uint64, env *messages.Envelope) (uint64, error) {
	key := destUUID
	s.messages[key] = append(s.messages[key], env)
	return uint64(len(s.messages[key])), nil
}

func (s *stubMessageStore) GetMessagesForDevice(_ context.Context, destUUID string, _ uint64) ([]*messages.Envelope, error) {
	return s.messages[destUUID], nil
}

func (s *stubMessageStore) Delete(_ context.Context, destUUID string, serverGUID string) error {
	return nil
}

func (s *stubMessageStore) DeleteForDevice(_ context.Context, destUUID string, _ uint64) error {
	return nil
}

func (s *stubMessageStore) DeleteForAccount(_ context.Context, uuid string) error {
	delete(s.messages, uuid)
	return nil
}

// errorMessageStore always returns errors from GetMessagesForDevice.
type errorMessageStore struct {
	stubMessageStore
}

func (s *errorMessageStore) GetMessagesForDevice(_ context.Context, _ string, _ uint64) ([]*messages.Envelope, error) {
	return nil, &accounts.InvalidArgumentError{Field: "test", Message: "simulated store error"}
}

func makeTestAccount(uuid, password string) *accounts.Account {
	// Hash the auth token so that the Handler's AuthTokenHash.Verify call
	// succeeds during authentication. The AccountsManager.Create would do this
	// automatically, but the stub store bypasses the manager, so we must hash
	// here to maintain correctness.
	tokenHash, err := auth.NewSaltedTokenHash(password)
	if err != nil {
		panic("makeTestAccount: failed to hash auth token: " + err.Error())
	}
	return &accounts.Account{
		UUID:   uuid,
		Number: "+15551234567",
		Devices: []accounts.Device{
			{
				ID:            accounts.PrimaryDeviceID,
				AuthToken:     password, // transient only
				AuthTokenHash: tokenHash,
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte{1, 2, 3},
					Signature: []byte{4, 5, 6},
				},
			},
		},
		IdentityKey: []byte{7, 8, 9},
	}
}

func TestNewHandler_NotNil(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
}

func TestNewHandler_FieldsSet(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)
	if h.accounts == nil {
		t.Error("accounts field is nil")
	}
	if h.messages == nil {
		t.Error("messages field is nil")
	}
	if h.sessions == nil {
		t.Error("sessions field is nil")
	}
	if h.logger == nil {
		t.Error("logger field is nil")
	}
}

func TestExtractCredentials_BasicAuth(t *testing.T) {
	logger := handlerTestLogger()
	h := &Handler{logger: logger}

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/", nil)
	req.SetBasicAuth("test-uuid", "my-password")

	uuid, pass, ok := h.extractCredentials(req)
	if !ok {
		t.Fatal("extractCredentials returned false for Basic Auth")
	}
	if uuid != "test-uuid" {
		t.Errorf("uuid = %q, want %q", uuid, "test-uuid")
	}
	if pass != "my-password" {
		t.Errorf("password = %q, want %q", pass, "my-password")
	}
}

func TestExtractCredentials_BasicAuth_WithDeviceID(t *testing.T) {
	logger := handlerTestLogger()
	h := &Handler{logger: logger}

	// Signal clients may send "uuid.deviceId" as the username.
	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/", nil)
	req.SetBasicAuth("test-uuid.1", "my-password")

	uuid, pass, ok := h.extractCredentials(req)
	if !ok {
		t.Fatal("extractCredentials returned false for Basic Auth with device ID")
	}
	if uuid != "test-uuid" {
		t.Errorf("uuid = %q, want %q", uuid, "test-uuid")
	}
	if pass != "my-password" {
		t.Errorf("password = %q, want %q", pass, "my-password")
	}
}

func TestExtractCredentials_QueryParams(t *testing.T) {
	logger := handlerTestLogger()
	h := &Handler{logger: logger}

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/?login=query-uuid&password=query-pass", nil)

	uuid, pass, ok := h.extractCredentials(req)
	if !ok {
		t.Fatal("extractCredentials returned false for query params")
	}
	if uuid != "query-uuid" {
		t.Errorf("uuid = %q, want %q", uuid, "query-uuid")
	}
	if pass != "query-pass" {
		t.Errorf("password = %q, want %q", pass, "query-pass")
	}
}

func TestExtractCredentials_QueryParams_WithDeviceID(t *testing.T) {
	logger := handlerTestLogger()
	h := &Handler{logger: logger}

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/?login=query-uuid.2&password=query-pass", nil)

	uuid, pass, ok := h.extractCredentials(req)
	if !ok {
		t.Fatal("extractCredentials returned false for query params with device ID")
	}
	if uuid != "query-uuid" {
		t.Errorf("uuid = %q, want %q", uuid, "query-uuid")
	}
	if pass != "query-pass" {
		t.Errorf("password = %q, want %q", pass, "query-pass")
	}
}

func TestExtractCredentials_NoCredentials(t *testing.T) {
	logger := handlerTestLogger()
	h := &Handler{logger: logger}

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/", nil)

	_, _, ok := h.extractCredentials(req)
	if ok {
		t.Error("extractCredentials returned true with no credentials")
	}
}

func TestExtractCredentials_EmptyLogin(t *testing.T) {
	logger := handlerTestLogger()
	h := &Handler{logger: logger}

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/?login=&password=pass", nil)

	_, _, ok := h.extractCredentials(req)
	if ok {
		t.Error("extractCredentials returned true with empty login")
	}
}

func TestExtractCredentials_EmptyPassword(t *testing.T) {
	logger := handlerTestLogger()
	h := &Handler{logger: logger}

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/?login=uuid&password=", nil)

	_, _, ok := h.extractCredentials(req)
	if ok {
		t.Error("extractCredentials returned true with empty password")
	}
}

func TestExtractCredentials_OnlyLoginNoPassword(t *testing.T) {
	logger := handlerTestLogger()
	h := &Handler{logger: logger}

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/?login=uuid", nil)

	_, _, ok := h.extractCredentials(req)
	if ok {
		t.Error("extractCredentials returned true with only login param")
	}
}

func TestExtractCredentials_BasicAuthTakesPrecedence(t *testing.T) {
	logger := handlerTestLogger()
	h := &Handler{logger: logger}

	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/?login=query-uuid&password=query-pass", nil)
	req.SetBasicAuth("basic-uuid", "basic-pass")

	uuid, pass, ok := h.extractCredentials(req)
	if !ok {
		t.Fatal("extractCredentials returned false")
	}
	if uuid != "basic-uuid" {
		t.Errorf("uuid = %q, want %q (Basic Auth should take precedence)", uuid, "basic-uuid")
	}
	if pass != "basic-pass" {
		t.Errorf("password = %q, want %q", pass, "basic-pass")
	}
}

func TestBuildEnvelopeRequest_ValidEnvelope(t *testing.T) {
	env := &messages.Envelope{
		ID:              42,
		Type:            messages.EnvelopeTypeCiphertext,
		SourceUUID:      "sender",
		DestinationUUID: "dest",
		Content:         []byte("encrypted"),
	}

	msg := buildEnvelopeRequest(1, env)
	if msg == nil {
		t.Fatal("buildEnvelopeRequest returned nil")
	}
	if msg.Type != "request" {
		t.Errorf("Type = %q, want %q", msg.Type, "request")
	}
	if msg.Request == nil {
		t.Fatal("Request is nil")
	}
	if msg.Request.ID != 1 {
		t.Errorf("Request.ID = %d, want %d", msg.Request.ID, 1)
	}
	if msg.Request.Verb != "PUT" {
		t.Errorf("Request.Verb = %q, want %q", msg.Request.Verb, "PUT")
	}
	if msg.Request.Path != "/api/v1/message" {
		t.Errorf("Request.Path = %q, want %q", msg.Request.Path, "/api/v1/message")
	}
	if msg.Request.Body == "" {
		t.Error("Request.Body is empty")
	}

	// Verify body is valid base64 containing JSON of the envelope.
	decoded, err := base64.StdEncoding.DecodeString(msg.Request.Body)
	if err != nil {
		t.Fatalf("body is not valid base64: %v", err)
	}
	var env2 messages.Envelope
	if err := json.Unmarshal(decoded, &env2); err != nil {
		t.Fatalf("body JSON unmarshal failed: %v", err)
	}
	if env2.ID != 42 {
		t.Errorf("decoded envelope ID = %d, want 42", env2.ID)
	}
}

func TestBuildEnvelopeRequest_DifferentIDs(t *testing.T) {
	env := &messages.Envelope{
		ID:              1,
		Type:            messages.EnvelopeTypePrekeyBundle,
		DestinationUUID: "dest",
	}

	tests := []uint64{0, 1, 100, 18446744073709551615}
	for _, id := range tests {
		msg := buildEnvelopeRequest(id, env)
		if msg == nil {
			t.Fatalf("buildEnvelopeRequest returned nil for id %d", id)
		}
		if msg.Request.ID != id {
			t.Errorf("Request.ID = %d, want %d", msg.Request.ID, id)
		}
	}
}

func TestBuildEnvelopeRequest_MinimalEnvelope(t *testing.T) {
	env := &messages.Envelope{}

	msg := buildEnvelopeRequest(1, env)
	if msg == nil {
		t.Fatal("buildEnvelopeRequest returned nil for empty envelope")
	}
	if msg.Request.Body == "" {
		t.Error("expected non-empty body even for empty envelope")
	}
}

// handleIncomingMessage is tested through the full WebSocket flow in
// TestHandleAuthenticated_FullWebSocket, TestHandleAuthenticated_MessagePUT,
// TestHandleAuthenticated_UnknownRoute, and TestHandleAuthenticated_ClientResponseAck.
// Direct unit tests are not possible because the Session struct has unexported
// fields (send channel, done channel) that must be initialized through NewSession.

func TestHandleAuthenticated_MissingCredentials(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	// Non-WebSocket request without credentials should get 401.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/", nil)
	h.HandleAuthenticated(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleAuthenticated_InvalidAccount(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/", nil)
	req.SetBasicAuth("nonexistent-uuid", "password")
	h.HandleAuthenticated(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleAuthenticated_WrongPassword(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["test-uuid"] = makeTestAccount("test-uuid", "correct-password")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/", nil)
	req.SetBasicAuth("test-uuid", "wrong-password")
	h.HandleAuthenticated(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleAuthenticated_NoPrimaryDevice(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	// Account with no primary device (device ID 2 only).
	acctStore.accounts["test-uuid"] = &accounts.Account{
		UUID:   "test-uuid",
		Number: "+15551234567",
		Devices: []accounts.Device{
			{
				ID:        2,
				AuthToken: "password",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte{1, 2, 3},
					Signature: []byte{4, 5, 6},
				},
			},
		},
		IdentityKey: []byte{7, 8, 9},
	}
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/", nil)
	req.SetBasicAuth("test-uuid", "password")
	h.HandleAuthenticated(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestHandleAuthenticated_FullWebSocket(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["ws-uuid"] = makeTestAccount("ws-uuid", "ws-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=ws-uuid&password=ws-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send a keepalive request using the protobuf wire format the server expects.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   10,
			Verb: "GET",
			Path: "/api/v1/keepalive",
		},
	})

	resp := wsRead(t, conn)
	if resp.Type != "response" {
		t.Errorf("response Type = %q, want %q", resp.Type, "response")
	}
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 10 {
		t.Errorf("Response.ID = %d, want 10", resp.Response.ID)
	}
	if resp.Response.Status != http.StatusOK {
		t.Errorf("Response.Status = %d, want %d", resp.Response.Status, http.StatusOK)
	}
}

func TestHandleAuthenticated_MessagePUT(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["msg-uuid"] = makeTestAccount("msg-uuid", "msg-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=msg-uuid&password=msg-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send a PUT message request using protobuf wire format.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   20,
			Verb: "PUT",
			Path: "/api/v1/message",
		},
	})

	resp := wsRead(t, conn)
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 20 {
		t.Errorf("Response.ID = %d, want 20", resp.Response.ID)
	}
	if resp.Response.Status != http.StatusOK {
		t.Errorf("Response.Status = %d, want %d", resp.Response.Status, http.StatusOK)
	}
}

func TestHandleAuthenticated_UnknownRoute(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["route-uuid"] = makeTestAccount("route-uuid", "route-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=route-uuid&password=route-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send an unknown route using protobuf wire format.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   30,
			Verb: "DELETE",
			Path: "/api/v1/unknown",
		},
	})

	resp := wsRead(t, conn)
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 30 {
		t.Errorf("Response.ID = %d, want 30", resp.Response.ID)
	}
	if resp.Response.Status != http.StatusNotFound {
		t.Errorf("Response.Status = %d, want %d", resp.Response.Status, http.StatusNotFound)
	}
}

func TestHandleAuthenticated_FlushPendingMessages(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["flush-uuid"] = makeTestAccount("flush-uuid", "flush-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	// Pre-populate pending messages.
	msgStore.messages["flush-uuid"] = []*messages.Envelope{
		{
			ID:              100,
			Type:            messages.EnvelopeTypeCiphertext,
			SourceUUID:      "sender-1",
			DestinationUUID: "flush-uuid",
			Content:         []byte("msg-1"),
		},
		{
			ID:              101,
			Type:            messages.EnvelopeTypePrekeyBundle,
			SourceUUID:      "sender-2",
			DestinationUUID: "flush-uuid",
			Content:         []byte("msg-2"),
		},
	}
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=flush-uuid&password=flush-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Read the two pending messages; server sends protobuf binary frames.
	for i := 0; i < 2; i++ {
		msg := wsRead(t, conn)
		if msg.Type != "request" {
			t.Errorf("pending message %d Type = %q, want %q", i, msg.Type, "request")
		}
		if msg.Request == nil {
			t.Fatalf("pending message %d Request is nil", i)
		}
		if msg.Request.Verb != "PUT" {
			t.Errorf("pending message %d Verb = %q, want %q", i, msg.Request.Verb, "PUT")
		}
		if msg.Request.Path != "/api/v1/message" {
			t.Errorf("pending message %d Path = %q, want %q", i, msg.Request.Path, "/api/v1/message")
		}
	}
}

func TestHandleAuthenticated_ClientResponseAck(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["ack-uuid"] = makeTestAccount("ack-uuid", "ack-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=ack-uuid&password=ack-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send a response (ack) message - server should not reply.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "response",
		Response: &signalws.WebSocketResponse{
			ID:     1,
			Status: 200,
		},
	})

	// After sending an ack, the server should not send any response.
	// We send a keepalive to verify the connection is still alive.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   99,
			Verb: "GET",
			Path: "/api/v1/keepalive",
		},
	})

	resp := wsRead(t, conn)
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 99 {
		t.Errorf("Response.ID = %d, want 99", resp.Response.ID)
	}
}

func TestHandleProvisioning_FullWebSocket(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleProvisioning(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/provisioning/"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// The server sends a protobuf-encoded WebSocketMessage containing a
	// PUT /v1/address request whose body is a proto-serialised ProvisioningAddress.
	msg := wsRead(t, conn)
	if msg.Type != "request" {
		t.Errorf("Type = %q, want %q", msg.Type, "request")
	}
	if msg.Request == nil {
		t.Fatal("Request is nil")
	}
	if msg.Request.Verb != "PUT" {
		t.Errorf("Verb = %q, want %q", msg.Request.Verb, "PUT")
	}
	if msg.Request.Path != "/v1/address" {
		t.Errorf("Path = %q, want %q", msg.Request.Path, "/v1/address")
	}
	if msg.Request.Body == "" {
		t.Fatal("body is empty, expected provisioning address")
	}

	// The body is base64(proto-serialised ProvisioningAddress).
	protoBytes, err := base64.StdEncoding.DecodeString(msg.Request.Body)
	if err != nil {
		t.Fatalf("body is not valid base64: %v", err)
	}
	var provAddr wsproto.ProvisioningAddress
	if err := proto.Unmarshal(protoBytes, &provAddr); err != nil {
		t.Fatalf("body is not a valid ProvisioningAddress proto: %v", err)
	}
	if provAddr.GetAddress() == "" {
		t.Error("provisioning address is empty")
	}

	// Send a protobuf-encoded response (ack) back.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "response",
		Response: &signalws.WebSocketResponse{
			ID:     msg.Request.ID,
			Status: 200,
		},
	})
	// The deferred conn.Close causes the server's ReadPump to return, completing
	// the handler. No explicit wait is needed because the test's assertions are
	// already done before this point.
}

func TestHandleAuthenticated_NilRequestIgnored(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["nil-req-uuid"] = makeTestAccount("nil-req-uuid", "nil-req-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=nil-req-uuid&password=nil-req-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send a protobuf-encoded message with type "request" but no Request field (nil).
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		// Request intentionally omitted — server must silently ignore it.
	})

	// Server should silently ignore it. Verify connection is still alive
	// by sending a keepalive.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   50,
			Verb: "GET",
			Path: "/api/v1/keepalive",
		},
	})

	resp := wsRead(t, conn)
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 50 {
		t.Errorf("Response.ID = %d, want 50", resp.Response.ID)
	}
}

func TestHandleAuthenticated_NoPendingMessages(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["empty-uuid"] = makeTestAccount("empty-uuid", "empty-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	// No pending messages in store.
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=empty-uuid&password=empty-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// With no pending messages, send a keepalive and verify the response.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   1,
			Verb: "GET",
			Path: "/api/v1/keepalive",
		},
	})

	resp := wsRead(t, conn)
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.Status != http.StatusOK {
		t.Errorf("Response.Status = %d, want %d", resp.Response.Status, http.StatusOK)
	}
}

func TestHandleAuthenticated_FlushPendingMessagesError(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["err-uuid"] = makeTestAccount("err-uuid", "err-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	errStore := &errorMessageStore{}
	msgMgr := messages.NewMessagesManager(errStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=err-uuid&password=err-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Even with message retrieval error, the connection should still work.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   1,
			Verb: "GET",
			Path: "/api/v1/keepalive",
		},
	})

	resp := wsRead(t, conn)
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.Status != http.StatusOK {
		t.Errorf("Response.Status = %d, want %d", resp.Response.Status, http.StatusOK)
	}
}

func TestHandleAuthenticated_NonWebSocketRequest(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["nonws-uuid"] = makeTestAccount("nonws-uuid", "nonws-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	// Non-websocket GET request with valid credentials - ws.Accept will fail.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/?login=nonws-uuid&password=nonws-pass", nil)
	h.HandleAuthenticated(rec, req)

	// ws.Accept fails for non-websocket requests; handler returns without writing status.
	// The response should not be a 101 upgrade.
	if rec.Code == http.StatusSwitchingProtocols {
		t.Error("expected non-101 status for non-websocket request")
	}
}

func TestHandleProvisioning_NonWebSocketRequest(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	// Non-websocket request - ws.Accept will fail.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/provisioning/", nil)
	h.HandleProvisioning(rec, req)

	if rec.Code == http.StatusSwitchingProtocols {
		t.Error("expected non-101 status for non-websocket request")
	}
}

func TestHandleProvisioning_ClientSendsNonResponse(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleProvisioning(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/provisioning/"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Read the protobuf-encoded provisioning address.
	wsRead(t, conn)

	// Send a request type message (not a response) using protobuf — server logs and ignores.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   5,
			Verb: "GET",
			Path: "/unexpected",
		},
	})
	// The deferred conn.Close terminates the server's ReadPump. No explicit
	// wait is needed since the test has no assertions after the write.
}

// marshalError is a typed error returned by the test marshal stub.
type marshalError struct {
	Message string
}

func (e *marshalError) Error() string {
	return "marshal error: " + e.Message
}

func TestBuildEnvelopeRequest_MarshalError(t *testing.T) {
	original := jsonMarshal
	t.Cleanup(func() { jsonMarshal = original })

	jsonMarshal = func(_ any) ([]byte, error) {
		return nil, &marshalError{Message: "simulated"}
	}

	env := &messages.Envelope{
		ID:              1,
		Type:            messages.EnvelopeTypeCiphertext,
		DestinationUUID: "dest",
	}
	msg := buildEnvelopeRequest(1, env)
	if msg != nil {
		t.Errorf("expected nil when marshal fails, got %v", msg)
	}
}

func TestBuildEnvelopeRequest_MarshalErrorReturnsNil(t *testing.T) {
	original := jsonMarshal
	t.Cleanup(func() { jsonMarshal = original })

	jsonMarshal = func(_ any) ([]byte, error) {
		return nil, &marshalError{Message: "envelope marshal failure"}
	}

	// Verify nil return for different envelope configurations.
	envelopes := []*messages.Envelope{
		{ID: 0},
		{ID: 100, Type: messages.EnvelopeTypePrekeyBundle, Content: []byte("data")},
	}
	for _, env := range envelopes {
		result := buildEnvelopeRequest(1, env)
		if result != nil {
			t.Errorf("expected nil for envelope ID %d, got non-nil", env.ID)
		}
	}
}

func TestFlushPendingMessages_SendError(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgStore.messages["closed-uuid"] = []*messages.Envelope{
		{
			ID:              1,
			Type:            messages.EnvelopeTypeCiphertext,
			SourceUUID:      "sender",
			DestinationUUID: "closed-uuid",
			Content:         []byte("msg"),
		},
	}
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)
	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	// handlerDone is closed by the server handler after completing, providing
	// deterministic synchronization instead of a fixed sleep.
	handlerDone := make(chan struct{})

	// Set up a real WebSocket connection and immediately close the session
	// to force the Send error path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Accept(w, r, &ws.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		session := signalws.NewSession(conn, "closed-uuid", 1, nil, logger)
		// Close the session immediately so Send returns an error.
		session.Close()
		// Call flushPendingMessages; the Send inside should fail.
		h.flushPendingMessages(r, session, "closed-uuid", 1)
		close(handlerDone)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/test"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Drain the client side so the server's WebSocket close handshake can
	// complete without blocking, allowing the handler to reach handlerDone.
	go func() {
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	}()

	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for handler to complete")
	}
}

func TestHandleIncomingMessage_SendErrorKeepalive(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)
	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	handlerDone := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Accept(w, r, &ws.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		session := signalws.NewSession(conn, "send-err-uuid", 1, nil, logger)
		// Close the session so Send fails.
		session.Close()
		// Simulate keepalive request handling with closed session.
		keepaliveMsg := &signalws.WebSocketMessage{
			Type: "request",
			Request: &signalws.WebSocketRequest{
				ID:   1,
				Verb: "GET",
				Path: "/api/v1/keepalive",
			},
		}
		h.handleIncomingMessage(session, keepaliveMsg)
		close(handlerDone)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/test"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	go func() {
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	}()

	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for handler to complete")
	}
}

func TestHandleIncomingMessage_SendErrorPUTMessage(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)
	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	handlerDone := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Accept(w, r, &ws.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		session := signalws.NewSession(conn, "put-err-uuid", 1, nil, logger)
		session.Close()
		putMsg := &signalws.WebSocketMessage{
			Type: "request",
			Request: &signalws.WebSocketRequest{
				ID:   1,
				Verb: "PUT",
				Path: "/api/v1/message",
			},
		}
		h.handleIncomingMessage(session, putMsg)
		close(handlerDone)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/test"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	go func() {
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	}()

	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for handler to complete")
	}
}

func TestHandleIncomingMessage_SendErrorUnknownRoute(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)
	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	handlerDone := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Accept(w, r, &ws.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		session := signalws.NewSession(conn, "unknown-err-uuid", 1, nil, logger)
		session.Close()
		unknownMsg := &signalws.WebSocketMessage{
			Type: "request",
			Request: &signalws.WebSocketRequest{
				ID:   1,
				Verb: "DELETE",
				Path: "/api/v1/unknown",
			},
		}
		h.handleIncomingMessage(session, unknownMsg)
		close(handlerDone)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/test"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	go func() {
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	}()

	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for handler to complete")
	}
}

func TestRouteToHTTP_NilHTTPHandler(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["nil-http-uuid"] = makeTestAccount("nil-http-uuid", "nil-http-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	// Create handler with nil httpHandler to exercise the 404 path.
	h := NewHandler(acctMgr, msgMgr, sessions, nil, logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=nil-http-uuid&password=nil-http-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send a request that triggers the default case (routeToHTTP).
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   40,
			Verb: "GET",
			Path: "/v1/some/endpoint",
		},
	})

	resp := wsRead(t, conn)
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 40 {
		t.Errorf("Response.ID = %d, want 40", resp.Response.ID)
	}
	if resp.Response.Status != http.StatusNotFound {
		t.Errorf("Response.Status = %d, want %d", resp.Response.Status, http.StatusNotFound)
	}
	if resp.Response.Message != "not found" {
		t.Errorf("Response.Message = %q, want %q", resp.Response.Message, "not found")
	}
}

func TestRouteToHTTP_NilHTTPHandler_ClosedSession(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	// Handler with nil httpHandler.
	h := NewHandler(acctMgr, msgMgr, sessions, nil, logger)

	handlerDone := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Accept(w, r, &ws.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		session := signalws.NewSession(conn, "nil-closed-uuid", 1, nil, logger)
		session.Close()
		msg := &signalws.WebSocketMessage{
			Type: "request",
			Request: &signalws.WebSocketRequest{
				ID:   1,
				Verb: "GET",
				Path: "/v1/some/path",
			},
		}
		// routeToHTTP with nil httpHandler on closed session: Send should fail.
		h.routeToHTTP(session, msg)
		close(handlerDone)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/test"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	go func() {
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	}()

	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for handler to complete")
	}
}

// TestRouteToHTTP_InvalidBase64Body verifies that routeToHTTP returns a 400
// response and sends it to the session when the body is not valid base64. This
// path is exercised via direct injection because the protobuf codec always
// produces valid base64 from wire bytes; a manually-constructed
// WebSocketMessage is required to trigger it.
func TestRouteToHTTP_InvalidBase64Body(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)
	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	handlerDone := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Accept(w, r, &ws.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		session := signalws.NewSession(conn, "b64-uuid", 1, nil, logger)
		session.StartWritePump()
		// Inject message with invalid base64 body directly into routeToHTTP.
		msg := &signalws.WebSocketMessage{
			Type: "request",
			Request: &signalws.WebSocketRequest{
				ID:   41,
				Verb: "PUT",
				Path: "/v1/some/endpoint",
				Body: "!!!not-valid-base64!!!",
			},
		}
		h.routeToHTTP(session, msg)

		// Drain the response from the send channel to confirm it was queued.
		select {
		case <-session.Done():
		case <-time.After(5 * time.Second):
		}
		close(handlerDone)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/test"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Read the 400 response from the session's write pump.
	readCtx, readCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readCancel()
	_, respData, err := conn.Read(readCtx)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	resp, err := signalws.UnmarshalFrame(respData, signalws.FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 41 {
		t.Errorf("Response.ID = %d, want 41", resp.Response.ID)
	}
	if resp.Response.Status != http.StatusBadRequest {
		t.Errorf("Response.Status = %d, want %d", resp.Response.Status, http.StatusBadRequest)
	}
	if resp.Response.Message != "invalid body encoding" {
		t.Errorf("Response.Message = %q, want %q", resp.Response.Message, "invalid body encoding")
	}

	<-handlerDone
}

func TestRouteToHTTP_InvalidBase64Body_ClosedSession(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	handlerDone := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Accept(w, r, &ws.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		session := signalws.NewSession(conn, "b64-closed-uuid", 1, nil, logger)
		session.Close()
		msg := &signalws.WebSocketMessage{
			Type: "request",
			Request: &signalws.WebSocketRequest{
				ID:   1,
				Verb: "PUT",
				Path: "/v1/endpoint",
				Body: "!!!not-valid-base64!!!",
			},
		}
		h.routeToHTTP(session, msg)
		close(handlerDone)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/test"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	go func() {
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	}()

	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for handler to complete")
	}
}

func TestRouteToHTTP_ValidBodyForwarded(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["fwd-uuid"] = makeTestAccount("fwd-uuid", "fwd-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	// Create an HTTP handler that echoes back the request body and status 200.
	echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	h := NewHandler(acctMgr, msgMgr, sessions, echoHandler, logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=fwd-uuid&password=fwd-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send a request with valid base64-encoded body using protobuf wire format.
	payload := `{"key":"value"}`
	encodedBody := base64.StdEncoding.EncodeToString([]byte(payload))
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   42,
			Verb: "PUT",
			Path: "/v1/custom/endpoint",
			Body: encodedBody,
		},
	})

	resp := wsRead(t, conn)
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 42 {
		t.Errorf("Response.ID = %d, want 42", resp.Response.ID)
	}
	if resp.Response.Status != http.StatusOK {
		t.Errorf("Response.Status = %d, want %d", resp.Response.Status, http.StatusOK)
	}

	// Decode the response body and verify the echo handler returned the original payload.
	if resp.Response.Body == "" {
		t.Fatal("Response.Body is empty, expected echoed payload")
	}
	decodedBody, err := base64.StdEncoding.DecodeString(resp.Response.Body)
	if err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if string(decodedBody) != payload {
		t.Errorf("Response body = %q, want %q", string(decodedBody), payload)
	}
}

func TestRouteToHTTP_BodyWithoutContentType_AutoSetsJSON(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["ct-uuid"] = makeTestAccount("ct-uuid", "ct-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	var receivedContentType string
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	})

	h := NewHandler(acctMgr, msgMgr, sessions, captureHandler, logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=ct-uuid&password=ct-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send request with body but no Content-Type header using protobuf wire format.
	payload := `{"data":"test"}`
	encodedBody := base64.StdEncoding.EncodeToString([]byte(payload))
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   43,
			Verb: "POST",
			Path: "/v1/auto-content-type",
			Body: encodedBody,
			// No Headers map, so Content-Type is not set.
		},
	})

	// Read but discard the response; we only care about what reached captureHandler.
	wsRead(t, conn)

	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", receivedContentType, "application/json")
	}
}

func TestRouteToHTTP_ExplicitContentType_NotOverridden(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["ct2-uuid"] = makeTestAccount("ct2-uuid", "ct2-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	var receivedContentType string
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	})

	h := NewHandler(acctMgr, msgMgr, sessions, captureHandler, logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=ct2-uuid&password=ct2-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send request with body AND explicit Content-Type using protobuf wire format.
	payload := `<xml>data</xml>`
	encodedBody := base64.StdEncoding.EncodeToString([]byte(payload))
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:      44,
			Verb:    "POST",
			Path:    "/v1/explicit-ct",
			Body:    encodedBody,
			Headers: map[string]string{"Content-Type": "application/xml"},
		},
	})

	// Read but discard the response; we only care about what reached captureHandler.
	wsRead(t, conn)

	if receivedContentType != "application/xml" {
		t.Errorf("Content-Type = %q, want %q", receivedContentType, "application/xml")
	}
}

func TestRouteToHTTP_HeadersForwarded(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["hdr-uuid"] = makeTestAccount("hdr-uuid", "hdr-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	var receivedAccept string
	var receivedCustom string
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAccept = r.Header.Get("Accept")
		receivedCustom = r.Header.Get("X-Custom-Header")
		w.Header().Set("X-Response-Header", "response-value")
		w.WriteHeader(http.StatusOK)
	})

	h := NewHandler(acctMgr, msgMgr, sessions, captureHandler, logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=hdr-uuid&password=hdr-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send request with custom headers using protobuf wire format.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   45,
			Verb: "GET",
			Path: "/v1/with-headers",
			Headers: map[string]string{
				"Accept":          "text/plain",
				"X-Custom-Header": "custom-value",
			},
		},
	})

	resp := wsRead(t, conn)

	if receivedAccept != "text/plain" {
		t.Errorf("Accept header = %q, want %q", receivedAccept, "text/plain")
	}
	if receivedCustom != "custom-value" {
		t.Errorf("X-Custom-Header = %q, want %q", receivedCustom, "custom-value")
	}

	// Verify response headers are forwarded back.
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.Headers == nil {
		t.Fatal("Response.Headers is nil")
	}
	if resp.Response.Headers["X-Response-Header"] != "response-value" {
		t.Errorf("Response X-Response-Header = %q, want %q",
			resp.Response.Headers["X-Response-Header"], "response-value")
	}
}

func TestRouteToHTTP_BasicAuthForwarded(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["auth-fwd-uuid"] = makeTestAccount("auth-fwd-uuid", "auth-fwd-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	var receivedUser string
	var receivedPass string
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUser, receivedPass, _ = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
	})

	h := NewHandler(acctMgr, msgMgr, sessions, captureHandler, logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=auth-fwd-uuid&password=auth-fwd-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send a request that gets routed to HTTP handler using protobuf wire format.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   46,
			Verb: "GET",
			Path: "/v1/auth-check",
		},
	})

	// Read but discard the response; we only care about captured credentials.
	wsRead(t, conn)

	if receivedUser != "auth-fwd-uuid" {
		t.Errorf("Basic Auth user = %q, want %q", receivedUser, "auth-fwd-uuid")
	}
	if receivedPass != "auth-fwd-pass" {
		t.Errorf("Basic Auth password = %q, want %q", receivedPass, "auth-fwd-pass")
	}
}

func TestRouteToHTTP_SendResponseError_ClosedSession(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	echoHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := NewHandler(acctMgr, msgMgr, sessions, echoHandler, logger)

	handlerDone := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Accept(w, r, &ws.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		session := signalws.NewSession(conn, "send-resp-err-uuid", 1, secrets.NewSecureString("token"), logger)
		// Close the session so the final Send in routeToHTTP fails.
		session.Close()
		msg := &signalws.WebSocketMessage{
			Type: "request",
			Request: &signalws.WebSocketRequest{
				ID:   1,
				Verb: "GET",
				Path: "/v1/some/path",
			},
		}
		h.routeToHTTP(session, msg)
		close(handlerDone)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/test"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	go func() {
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	}()

	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for handler to complete")
	}
}

func TestRouteToHTTP_NoBody_NoContentTypeSet(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["nobody-uuid"] = makeTestAccount("nobody-uuid", "nobody-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	var receivedContentType string
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	})

	h := NewHandler(acctMgr, msgMgr, sessions, captureHandler, logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=nobody-uuid&password=nobody-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send request with no body using protobuf wire format.
	// Content-Type should NOT be auto-set because there is no body.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   47,
			Verb: "GET",
			Path: "/v1/no-body",
		},
	})

	// Read but discard the response; we only care about captured Content-Type.
	wsRead(t, conn)

	if receivedContentType != "" {
		t.Errorf("Content-Type = %q, want empty (no body, should not auto-set)", receivedContentType)
	}
}

func TestRouteToHTTP_ResponseHeaders_Empty(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctStore.accounts["emptyhdr-uuid"] = makeTestAccount("emptyhdr-uuid", "emptyhdr-pass")
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	// Handler that returns no explicit headers or body.
	bareHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	h := NewHandler(acctMgr, msgMgr, sessions, bareHandler, logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleAuthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/?login=emptyhdr-uuid&password=emptyhdr-pass"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   48,
			Verb: "DELETE",
			Path: "/v1/no-content",
		},
	})

	resp := wsRead(t, conn)
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 48 {
		t.Errorf("Response.ID = %d, want 48", resp.Response.ID)
	}
	if resp.Response.Status != http.StatusNoContent {
		t.Errorf("Response.Status = %d, want %d", resp.Response.Status, http.StatusNoContent)
	}
	if resp.Response.Body != "" {
		t.Errorf("Response.Body = %q, want empty", resp.Response.Body)
	}
}

func TestHandleProvisioning_SendProvisioningAddressError(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)
	_ = NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	handlerDone := make(chan struct{})

	// Test the provisioning send error path by creating a WebSocket
	// connection and closing the session before sending the provisioning
	// address. We use a custom handler that manually simulates the
	// HandleProvisioning flow with a pre-closed session.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Accept(w, r, &ws.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		session := signalws.NewSession(conn, "provision-addr", 0, nil, logger)
		// Close session immediately so Send fails.
		session.Close()

		addrMsg := &signalws.WebSocketMessage{
			Type: "request",
			Request: &signalws.WebSocketRequest{
				ID:   1,
				Verb: "PUT",
				Path: "/v1/address",
				Body: mustMarshalBase64(map[string]string{"uuid": "provision-addr"}),
			},
		}
		// This Send should fail because the session is closed.
		err = session.Send(addrMsg)
		if err == nil {
			t.Error("expected error from Send on closed session")
		}
		close(handlerDone)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/provisioning/"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	go func() {
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	}()

	select {
	case <-handlerDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for handler to complete")
	}
}

// --------------------------------------------------------------------------
// NewHandler / origin validation (task: WebSocket origin hardening)
// --------------------------------------------------------------------------

func TestNewHandler_NoInsecureSkipVerify_NoAllowedOrigins(t *testing.T) {
	// When no allowedOrigins are provided, acceptOptions must not set
	// InsecureSkipVerify. The library default (same-origin) check applies.
	acctStore := newStubAccountStore()
	msgStore := newStubMessageStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 6)
	msgMgr := messages.NewMessagesManager(msgStore)
	logger := handlerTestLogger()
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, nil, logger)

	opts := h.acceptOptions()
	if opts.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be false")
	}
	if len(opts.OriginPatterns) != 0 {
		t.Errorf("expected empty OriginPatterns, got %v", opts.OriginPatterns)
	}
}

func TestNewHandler_AcceptOptions_WithAllowedOrigins(t *testing.T) {
	acctStore := newStubAccountStore()
	msgStore := newStubMessageStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 6)
	msgMgr := messages.NewMessagesManager(msgStore)
	logger := handlerTestLogger()
	sessions := signalws.NewSessionManager(logger)

	origins := []string{"https://signal.example.com", "https://app.signal.org"}
	h := NewHandler(acctMgr, msgMgr, sessions, nil, logger, origins...)

	opts := h.acceptOptions()
	if opts.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be false even with allowed origins")
	}
	if len(opts.OriginPatterns) != 2 {
		t.Fatalf("expected 2 OriginPatterns, got %d", len(opts.OriginPatterns))
	}
	if opts.OriginPatterns[0] != origins[0] {
		t.Errorf("expected first origin %q, got %q", origins[0], opts.OriginPatterns[0])
	}
}

func TestNewHandler_AllowedOriginsStoredCorrectly(t *testing.T) {
	acctStore := newStubAccountStore()
	msgStore := newStubMessageStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 6)
	msgMgr := messages.NewMessagesManager(msgStore)
	logger := handlerTestLogger()
	sessions := signalws.NewSessionManager(logger)

	origin := "https://signal.example.com"
	h := NewHandler(acctMgr, msgMgr, sessions, nil, logger, origin)

	if len(h.allowedOrigins) != 1 || h.allowedOrigins[0] != origin {
		t.Errorf("expected allowedOrigins [%q], got %v", origin, h.allowedOrigins)
	}
}

func TestNewHandler_EmptyAllowedOrigins_NoInsecureBypass(t *testing.T) {
	acctStore := newStubAccountStore()
	msgStore := newStubMessageStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 6)
	msgMgr := messages.NewMessagesManager(msgStore)
	logger := handlerTestLogger()
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, nil, logger)
	if len(h.allowedOrigins) != 0 {
		t.Errorf("expected empty allowedOrigins, got %v", h.allowedOrigins)
	}

	opts := h.acceptOptions()
	if opts.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must not be set even with empty origins")
	}
}
