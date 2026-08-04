package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/service"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// WebUIHandler provides client-facing REST endpoints for the web UI.
// These wrap the SDK client to provide high-level operations (send message,
// list conversations, etc.) that the React WebAdapter calls. The browser
// cannot perform Signal Protocol encryption directly, so these endpoints
// handle encryption/decryption server-side via the SDK.
type WebUIHandler struct {
	client        *signal.Client
	callSignaling service.CallSignalingService
}

// NewWebUIHandler creates a web UI handler wrapping the given SDK client.
func NewWebUIHandler(client *signal.Client, callSvc service.CallSignalingService) *WebUIHandler {
	return &WebUIHandler{client: client, callSignaling: callSvc}
}

// RegisterRoutes registers all /api/v1/* routes on the mux.
func (h *WebUIHandler) RegisterRoutes(mux *http.ServeMux) {
	// Account
	mux.HandleFunc("GET /api/v1/account/registered", h.handleIsRegistered)
	mux.HandleFunc("GET /api/v1/account/whoami", h.handleWhoAmI)
	mux.HandleFunc("POST /api/v1/account/verify/session", h.handleCreateVerificationSession)
	mux.HandleFunc("POST /api/v1/account/verify/code", h.handleRequestVerificationCode)
	mux.HandleFunc("POST /api/v1/account/verify/submit", h.handleSubmitVerificationCode)
	mux.HandleFunc("POST /api/v1/account/register", h.handleRegister)

	// Messaging
	mux.HandleFunc("POST /api/v1/messages/send", h.handleSendMessage)
	mux.HandleFunc("GET /api/v1/messages", h.handleGetMessages)
	mux.HandleFunc("GET /api/v1/conversations", h.handleGetConversations)

	// Contacts
	mux.HandleFunc("GET /api/v1/contacts", h.handleListContacts)

	// Calling
	mux.HandleFunc("POST /api/v1/call/offer", h.handleCallOfferRelay)
	mux.HandleFunc("POST /api/v1/call/answer", h.handleCallAnswerRelay)
	mux.HandleFunc("POST /api/v1/call/ice", h.handleCallICERelay)
	mux.HandleFunc("POST /api/v1/call/hangup", h.handleCallHangupRelay)
}

func (h *WebUIHandler) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func (h *WebUIHandler) writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (h *WebUIHandler) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (h *WebUIHandler) readJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// --- Account ---

func (h *WebUIHandler) handleIsRegistered(w http.ResponseWriter, r *http.Request) {
	creds, err := h.client.Config().Store.GetCredentials()
	registered := err == nil && creds != nil && creds.UUID != ""
	h.writeJSON(w, registered)
}

func (h *WebUIHandler) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.ctx()
	defer cancel()
	account, err := h.client.WhoAmI(ctx)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, account)
}

func (h *WebUIHandler) handleCreateVerificationSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Number string `json:"number"`
	}
	if err := h.readJSON(r, &body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ctx, cancel := h.ctx()
	defer cancel()
	session, err := h.client.CreateVerificationSession(ctx, body.Number)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, session)
}

func (h *WebUIHandler) handleRequestVerificationCode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionID string `json:"sessionId"`
	}
	if err := h.readJSON(r, &body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ctx, cancel := h.ctx()
	defer cancel()
	session, err := h.client.RequestVerificationCode(ctx, body.SessionID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, session)
}

func (h *WebUIHandler) handleSubmitVerificationCode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionID string `json:"sessionId"`
		Code      string `json:"code"`
	}
	if err := h.readJSON(r, &body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ctx, cancel := h.ctx()
	defer cancel()
	session, err := h.client.SubmitVerificationCode(ctx, body.SessionID, body.Code)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, session)
}

func (h *WebUIHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Number    string `json:"number"`
		SessionID string `json:"sessionId"`
	}
	if err := h.readJSON(r, &body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ctx, cancel := h.ctx()
	defer cancel()
	result, err := h.client.Register(ctx, body.Number, body.SessionID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, result)
}

// --- Messaging ---

func (h *WebUIHandler) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Recipient string `json:"recipient"`
		Text      string `json:"text"`
	}
	if err := h.readJSON(r, &body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ctx, cancel := h.ctx()
	defer cancel()
	result, err := h.client.Send(ctx, body.Recipient, body.Text, nil)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, result)
}

func (h *WebUIHandler) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	conversationID := r.URL.Query().Get("conversationId")
	if conversationID == "" {
		h.writeError(w, http.StatusBadRequest, "conversationId required")
		return
	}
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	store := h.client.Config().Store
	messages, err := store.GetMessages(conversationID, limit)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, messages)
}

func (h *WebUIHandler) handleGetConversations(w http.ResponseWriter, r *http.Request) {
	// Get conversations from the DAO store.
	daoStore, ok := h.client.Config().Store.(*signal.DAOStore)
	if !ok {
		h.writeJSON(w, []interface{}{})
		return
	}
	ctx, cancel := h.ctx()
	defer cancel()
	convs, err := daoStore.Factory().Conversations.Find(ctx).
		OrderBy("ActiveAt").
		Execute()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, convs)
}

// --- Contacts ---

func (h *WebUIHandler) handleListContacts(w http.ResponseWriter, r *http.Request) {
	store := h.client.Config().Store
	contacts, err := store.GetContacts()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.writeJSON(w, contacts)
}

// --- Calling (relay to/from WebRTC signaling) ---

func (h *WebUIHandler) handleCallOfferRelay(w http.ResponseWriter, r *http.Request) {
	h.relayCall(w, r, func(svc service.CallSignalingService, senderUUID string, msg *calling.CallSignalMessage) error {
		msg.CallerUUID = senderUUID
		return svc.RelayOffer(r.Context(), senderUUID, msg)
	})
}

func (h *WebUIHandler) handleCallAnswerRelay(w http.ResponseWriter, r *http.Request) {
	h.relayCall(w, r, func(svc service.CallSignalingService, senderUUID string, msg *calling.CallSignalMessage) error {
		msg.CalleeUUID = senderUUID
		return svc.RelayAnswer(r.Context(), senderUUID, msg)
	})
}

func (h *WebUIHandler) handleCallICERelay(w http.ResponseWriter, r *http.Request) {
	h.relayCall(w, r, func(svc service.CallSignalingService, senderUUID string, msg *calling.CallSignalMessage) error {
		return svc.RelayICECandidate(r.Context(), senderUUID, msg)
	})
}

func (h *WebUIHandler) handleCallHangupRelay(w http.ResponseWriter, r *http.Request) {
	h.relayCall(w, r, func(svc service.CallSignalingService, senderUUID string, msg *calling.CallSignalMessage) error {
		return svc.RelayHangup(r.Context(), senderUUID, msg)
	})
}

// relayCall decodes a CallSignalMessage and delegates to the provided relay function.
func (h *WebUIHandler) relayCall(w http.ResponseWriter, r *http.Request,
	fn func(service.CallSignalingService, string, *calling.CallSignalMessage) error) {
	if h.callSignaling == nil {
		h.writeError(w, http.StatusServiceUnavailable, "call signaling not available")
		return
	}

	var msg calling.CallSignalMessage
	if err := h.readJSON(r, &msg); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid call signal message")
		return
	}

	// Get sender UUID from stored credentials.
	creds, err := h.client.Config().Store.GetCredentials()
	if err != nil || creds == nil {
		h.writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	if err := fn(h.callSignaling, creds.UUID, &msg); err != nil {
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
