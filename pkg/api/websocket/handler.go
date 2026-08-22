// Package websocket provides the HTTP upgrade handlers for WebSocket
// connections, including authenticated messaging sessions and device
// provisioning sessions.
package websocket

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	ws "github.com/coder/websocket"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/auth"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
	pb "github.com/jeremyhahn/go-signal/pkg/websocket/wsproto"
)

// Handler upgrades HTTP connections to WebSocket and manages the session
// lifecycle for both authenticated messaging and device provisioning.
type Handler struct {
	accounts       *accounts.AccountsManager
	messages       *messages.MessagesManager
	sessions       *signalws.SessionManager
	httpHandler    http.Handler
	logger         *slog.Logger
	allowedOrigins []string
	// dummyHash is pre-computed at construction time and used in
	// HandleAuthenticated to equalise timing when an account UUID is not
	// found, preventing timing-based UUID existence oracle attacks.
	dummyHash *auth.SaltedTokenHash
}

// NewHandler creates a new WebSocket Handler. The httpHandler parameter is the
// HTTP mux/handler chain used for REST API routing. WebSocket requests that are
// not handled directly (keepalive, message ack) are forwarded through
// httpHandler, mirroring the Java Signal-Server's WebSocketResourceProvider.
// allowedOrigins is the list of Origin header values that are permitted for
// WebSocket upgrades. When non-empty, only those origins are accepted. When
// empty, the library default (same-origin) check applies.
func NewHandler(
	accts *accounts.AccountsManager,
	msgs *messages.MessagesManager,
	sessions *signalws.SessionManager,
	httpHandler http.Handler,
	logger *slog.Logger,
	allowedOrigins ...string,
) *Handler {
	// Pre-compute a dummy hash so that HandleAuthenticated can call Verify on
	// account-not-found paths to equalise timing with the real auth path.
	dummyHash, _ := auth.NewSaltedTokenHash("dummy-timing-equalization-token")
	return &Handler{
		accounts:       accts,
		messages:       msgs,
		sessions:       sessions,
		httpHandler:    httpHandler,
		logger:         logger.With(slog.String("component", "websocket-handler")),
		allowedOrigins: allowedOrigins,
		dummyHash:      dummyHash,
	}
}

// acceptOptions builds the websocket.AcceptOptions for this handler. Origin
// checking is performed using the configured allowed origins list; the
// InsecureSkipVerify flag is never set.
func (h *Handler) acceptOptions() *ws.AcceptOptions {
	if len(h.allowedOrigins) == 0 {
		// No explicit origins: rely on the library's default same-origin check.
		return &ws.AcceptOptions{}
	}
	return &ws.AcceptOptions{
		OriginPatterns: h.allowedOrigins,
	}
}

// HandleAuthenticated upgrades the HTTP connection to a WebSocket, validates
// credentials, and manages the authenticated messaging session. The client
// receives any pending messages upon connection.
func (h *Handler) HandleAuthenticated(w http.ResponseWriter, r *http.Request) {
	// Extract credentials from Basic Auth header or query parameters.
	acctUUID, password, ok := h.extractCredentials(r)
	if !ok {
		http.Error(w, "missing credentials", http.StatusUnauthorized)
		return
	}

	// Validate credentials.
	acct, err := h.accounts.Get(r.Context(), acctUUID)
	if err != nil {
		// Perform a real hash verification to equalise timing so that
		// response latency does not reveal whether the UUID exists.
		h.dummyHash.Verify(password)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify the password against the primary device's stored token hash.
	// The constant-time comparison is encapsulated inside AuthTokenHash.Verify.
	primary := acct.PrimaryDevice()
	if primary == nil || !primary.AuthTokenHash.Verify(password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	// Seal the session credential before the upgrade: once the connection is
	// hijacked there is no HTTP status left to report a failure with, and a
	// session must never run with an unprotected (or unset) password.
	sessionPassword, err := secrets.NewSecureString(password)
	if err != nil {
		h.logger.Error("failed to protect session credential", slog.String("error", err.Error()))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Upgrade to WebSocket with validated origin checking.
	conn, err := ws.Accept(w, r, h.acceptOptions())
	if err != nil {
		sessionPassword.Destroy()
		h.logger.Error("websocket upgrade failed", slog.String("error", err.Error()))
		return
	}

	deviceID := accounts.PrimaryDeviceID
	session := signalws.NewSession(conn, acct.UUID, deviceID, sessionPassword, h.logger)
	// Do NOT force a frame format here. ReadPump auto-detects the format from
	// the first inbound frame type (binary → protobuf, text → JSON). Forcing
	// protobuf here would lock the session before ReadPump can detect a JSON
	// text frame, causing parse failures for JSON clients (integration tests,
	// debugging tools). Signal app clients naturally send binary frames and
	// ReadPump will detect protobuf correctly on their first message.

	// Start the write pump BEFORE registering the session so that any
	// messages delivered via the DeliveryCallback are consumed immediately
	// rather than sitting in the send channel with no reader.
	session.StartWritePump()

	h.sessions.Register(session)
	defer func() {
		h.sessions.Unregister(session)
		session.Close()
	}()

	// Flush pending messages to the newly connected client.
	h.flushPendingMessages(r, session, acct.UUID, deviceID)

	// The read pump blocks until the connection closes.
	session.ReadPump(func(msg *signalws.WebSocketMessage) {
		h.handleIncomingMessage(session, msg)
	})
}

// HandleUnauthenticated upgrades the HTTP connection to a WebSocket without
// requiring credentials. This is used by clients for operations that don't
// need authentication, such as fetching remote config via WebSocket transport.
func (h *Handler) HandleUnauthenticated(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.Accept(w, r, h.acceptOptions())
	if err != nil {
		h.logger.Error("unauthenticated websocket upgrade failed", slog.String("error", err.Error()))
		return
	}

	sessionUUID := uuid.New().String()
	session := signalws.NewSession(conn, sessionUUID, 0, nil, h.logger)
	// Do NOT force a frame format here; ReadPump auto-detects from the first
	// inbound frame type, supporting both JSON (integration tests) and protobuf
	// (Signal app clients) without a config knob.
	session.StartWritePump()

	h.sessions.Register(session)
	defer func() {
		h.sessions.Unregister(session)
		session.Close()
	}()

	// The unauthenticated socket handles WebSocket-wrapped HTTP requests.
	session.ReadPump(func(msg *signalws.WebSocketMessage) {
		h.handleIncomingMessage(session, msg)
	})
}

// HandleProvisioning upgrades the HTTP connection to a WebSocket for the
// device provisioning flow. No authentication is required. The server assigns
// a provisioning address and waits for the primary device to complete the
// provisioning.
func (h *Handler) HandleProvisioning(w http.ResponseWriter, r *http.Request) {
	conn, err := ws.Accept(w, r, h.acceptOptions())
	if err != nil {
		h.logger.Error("provisioning websocket upgrade failed", slog.String("error", err.Error()))
		return
	}

	// Generate a random provisioning address (base64url-encoded random
	// bytes), matching the official Signal-Server format.
	addrBytes := make([]byte, 16)
	if _, err := rand.Read(addrBytes); err != nil {
		h.logger.Error("failed to generate provisioning address", slog.String("error", err.Error()))
		return
	}
	provisioningAddr := base64.RawURLEncoding.EncodeToString(addrBytes)

	// Create a temporary session for provisioning (device ID 0 indicates
	// provisioning).
	session := signalws.NewSession(conn, provisioningAddr, 0, nil, h.logger)
	// Signal clients (libsignal-client, signal-cli) use binary protobuf
	// framing for WebSocket messages. Force protobuf before sending the
	// first message since format auto-detection only triggers on inbound
	// messages and we send before the client does.
	session.SetFormat(signalws.FrameFormatProtobuf)

	h.sessions.Register(session)
	defer func() {
		h.sessions.Unregister(session)
		session.Close()
	}()

	// Start the write pump before sending messages so the send channel has
	// a consumer.
	session.StartWritePump()

	// Encode the provisioning address as a protobuf ProvisioningAddress
	// message (matching the official Signal-Server).
	provAddr := &pb.ProvisioningAddress{
		Address: &provisioningAddr,
	}
	bodyBytes, err := proto.Marshal(provAddr)
	if err != nil {
		h.logger.Error("failed to marshal provisioning address", slog.String("error", err.Error()))
		return
	}

	// Send the provisioning address to the client with the required
	// X-Signal-Timestamp header.
	addrMsg := &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:      1,
			Verb:    "PUT",
			Path:    "/v1/address",
			Body:    base64.StdEncoding.EncodeToString(bodyBytes),
			Headers: map[string]string{"X-Signal-Timestamp": fmt.Sprintf("%d", time.Now().UnixMilli())},
		},
	}
	if err := session.Send(addrMsg); err != nil {
		h.logger.Error("failed to send provisioning address", slog.String("error", err.Error()))
		return
	}

	// Read pump blocks until connection closes.
	session.ReadPump(func(msg *signalws.WebSocketMessage) {
		// During provisioning, the client primarily sends responses to
		// server-initiated requests. Any unexpected messages are logged.
		if msg.Type == "response" {
			h.logger.Debug("received provisioning response",
				slog.Uint64("id", msg.Response.ID),
				slog.Int("status", msg.Response.Status))
		}
	})
}

// flushPendingMessages retrieves all pending messages for the device and sends
// them to the connected WebSocket session.
func (h *Handler) flushPendingMessages(r *http.Request, session *signalws.Session, acctUUID string, deviceID uint64) {
	envelopes, err := h.messages.GetMessagesForDevice(r.Context(), acctUUID, deviceID)
	if err != nil {
		h.logger.Error("failed to get pending messages",
			slog.String("uuid", acctUUID),
			slog.String("error", err.Error()))
		return
	}

	for i, env := range envelopes {
		msg := buildEnvelopeRequest(uint64(i+1), env)
		if msg == nil {
			// The message stays queued, so skipping costs a redelivery
			// attempt rather than the message itself.
			h.logger.Error("failed to encode pending envelope",
				slog.String("uuid", acctUUID))
			continue
		}
		if err := session.Send(msg); err != nil {
			h.logger.Warn("failed to send pending message",
				slog.String("uuid", acctUUID),
				slog.String("error", err.Error()))
			return
		}
	}
}

// handleIncomingMessage processes an incoming WebSocket message from an
// authenticated client.
func (h *Handler) handleIncomingMessage(session *signalws.Session, msg *signalws.WebSocketMessage) {
	if msg.Type == "response" {
		// Client is acknowledging a server-sent message.
		h.logger.Debug("received message ack",
			slog.String("uuid", session.UUID),
			slog.Uint64("id", msg.Response.ID),
			slog.Int("status", msg.Response.Status))
		return
	}

	if msg.Request == nil {
		return
	}

	// Handle client-initiated requests.
	switch {
	case msg.Request.Verb == "GET" && msg.Request.Path == "/api/v1/keepalive":
		resp := &signalws.WebSocketMessage{
			Type: "response",
			Response: &signalws.WebSocketResponse{
				ID:      msg.Request.ID,
				Status:  http.StatusOK,
				Message: "OK",
			},
		}
		if err := session.Send(resp); err != nil {
			h.logger.Warn("failed to send keepalive response",
				slog.String("uuid", session.UUID),
				slog.String("error", err.Error()))
		}

	case msg.Request.Verb == "PUT" && msg.Request.Path == "/api/v1/message":
		// Message acknowledgment from client; respond with 200.
		resp := &signalws.WebSocketMessage{
			Type: "response",
			Response: &signalws.WebSocketResponse{
				ID:      msg.Request.ID,
				Status:  http.StatusOK,
				Message: "OK",
			},
		}
		if err := session.Send(resp); err != nil {
			h.logger.Warn("failed to send message ack response",
				slog.String("uuid", session.UUID),
				slog.String("error", err.Error()))
		}

	default:
		// Route the request through the HTTP handler chain, mirroring the
		// Java Signal-Server's WebSocketResourceProvider which forwards all
		// WebSocket requests to the same REST handlers.
		h.routeToHTTP(session, msg)
	}
}

// extractCredentials extracts the account UUID and password from either Basic
// Auth headers or query parameters (login/password).
func (h *Handler) extractCredentials(r *http.Request) (string, string, bool) {
	// Try Basic Auth first.
	username, password, ok := r.BasicAuth()
	if ok {
		acctUUID := username
		if idx := strings.IndexByte(username, '.'); idx >= 0 {
			acctUUID = username[:idx]
		}
		return acctUUID, password, true
	}

	// Fall back to query parameters.
	login := r.URL.Query().Get("login")
	pass := r.URL.Query().Get("password")
	if login != "" && pass != "" {
		acctUUID := login
		if idx := strings.IndexByte(login, '.'); idx >= 0 {
			acctUUID = login[:idx]
		}
		return acctUUID, pass, true
	}

	return "", "", false
}

// routeToHTTP forwards a WebSocket request through the HTTP handler chain,
// mirroring the Java Signal-Server's WebSocketResourceProvider. This allows
// WebSocket clients to invoke any REST endpoint (e.g. PUT /v1/messages/{dest}
// for typing indicators) without duplicating handler logic.
func (h *Handler) routeToHTTP(session *signalws.Session, msg *signalws.WebSocketMessage) {
	if h.httpHandler == nil {
		h.logger.Warn("no HTTP handler configured for WebSocket routing",
			slog.String("uuid", session.UUID),
			slog.String("verb", msg.Request.Verb),
			slog.String("path", msg.Request.Path))
		resp := &signalws.WebSocketMessage{
			Type: "response",
			Response: &signalws.WebSocketResponse{
				ID:      msg.Request.ID,
				Status:  http.StatusNotFound,
				Message: "not found",
			},
		}
		if err := session.Send(resp); err != nil {
			h.logger.Warn("failed to send error response",
				slog.String("uuid", session.UUID),
				slog.String("error", err.Error()))
		}
		return
	}

	// Decode the body from base64 if present.
	var bodyReader io.Reader = http.NoBody
	if msg.Request.Body != "" {
		bodyBytes, err := base64.StdEncoding.DecodeString(msg.Request.Body)
		if err != nil {
			h.logger.Warn("failed to decode WebSocket request body",
				slog.String("uuid", session.UUID),
				slog.String("error", err.Error()))
			resp := &signalws.WebSocketMessage{
				Type: "response",
				Response: &signalws.WebSocketResponse{
					ID:      msg.Request.ID,
					Status:  http.StatusBadRequest,
					Message: "invalid body encoding",
				},
			}
			if err := session.Send(resp); err != nil {
				h.logger.Warn("failed to send decode error response",
					slog.String("uuid", session.UUID),
					slog.String("error", err.Error()))
			}
			return
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	// Build an in-memory HTTP request from the WebSocket message.
	httpReq, err := http.NewRequest(msg.Request.Verb, msg.Request.Path, bodyReader)
	if err != nil {
		h.logger.Warn("failed to create HTTP request from WebSocket message",
			slog.String("uuid", session.UUID),
			slog.String("error", err.Error()))
		resp := &signalws.WebSocketMessage{
			Type: "response",
			Response: &signalws.WebSocketResponse{
				ID:      msg.Request.ID,
				Status:  http.StatusInternalServerError,
				Message: "internal error",
			},
		}
		if err := session.Send(resp); err != nil {
			h.logger.Warn("failed to send internal error response",
				slog.String("uuid", session.UUID),
				slog.String("error", err.Error()))
		}
		return
	}

	// Forward headers from the WebSocket request.
	for k, v := range msg.Request.Headers {
		httpReq.Header.Set(k, v)
	}

	// Set Basic Auth using the session's credentials so that the REST auth
	// middleware can authenticate the request.
	if session.AuthToken != nil && !session.AuthToken.IsDestroyed() {
		httpReq.SetBasicAuth(session.UUID, session.AuthToken.Plaintext())
	}

	// Set content type if not already set and there's a body.
	if httpReq.Header.Get("Content-Type") == "" && msg.Request.Body != "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	// Execute the request through the HTTP handler.
	recorder := httptest.NewRecorder()
	h.httpHandler.ServeHTTP(recorder, httpReq)

	h.logger.Info("routed WebSocket request to HTTP handler",
		slog.String("uuid", session.UUID),
		slog.String("verb", msg.Request.Verb),
		slog.String("path", msg.Request.Path),
		slog.Int("status", recorder.Code),
		slog.Int("bodyLen", recorder.Body.Len()))

	// Build the WebSocket response from the HTTP response.
	respBody := ""
	if recorder.Body.Len() > 0 {
		respBody = base64.StdEncoding.EncodeToString(recorder.Body.Bytes())
	}

	respHeaders := make(map[string]string, len(recorder.Header()))
	for k, v := range recorder.Header() {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}

	resp := &signalws.WebSocketMessage{
		Type: "response",
		Response: &signalws.WebSocketResponse{
			ID:      msg.Request.ID,
			Status:  recorder.Code,
			Message: http.StatusText(recorder.Code),
			Body:    respBody,
			Headers: respHeaders,
		},
	}

	if err := session.Send(resp); err != nil {
		h.logger.Warn("failed to send HTTP-routed response",
			slog.String("uuid", session.UUID),
			slog.String("error", err.Error()))
	}
}

// buildEnvelopeRequest wraps an envelope in the PUT /api/v1/message request
// every Signal client reads messages from. The body is the envelope's
// protobuf wire form — clients parse it with the generated protobuf reader,
// so it must not be JSON. Returns nil when the envelope cannot be marshalled;
// the caller drops the delivery rather than sending a body no client can read.
func buildEnvelopeRequest(id uint64, env *messages.Envelope) *signalws.WebSocketMessage {
	body, err := messages.MarshalEnvelope(env)
	if err != nil {
		return nil
	}

	return &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   id,
			Verb: "PUT",
			Path: "/api/v1/message",
			Body: encodeBase64(body),
		},
	}
}
