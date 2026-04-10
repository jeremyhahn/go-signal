package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/coder/websocket"
)

// WebUIEventHub manages WebSocket connections for the web UI.
// When the SDK client receives messages via its WebSocket to the Signal
// server, events are broadcast to all connected web UI browsers.
type WebUIEventHub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]struct{}
}

// NewWebUIEventHub creates an event hub for web UI clients.
func NewWebUIEventHub() *WebUIEventHub {
	return &WebUIEventHub{
		clients: make(map[*websocket.Conn]struct{}),
	}
}

// HandleWebSocket upgrades the HTTP connection to WebSocket and registers
// the client for event delivery. The connection is held open until the
// client disconnects or the server shuts down.
func (h *WebUIEventHub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Allow all origins for development. Production should restrict
		// this to the signald host.
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer conn.CloseNow()

	h.mu.Lock()
	h.clients[conn] = struct{}{}
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, conn)
		h.mu.Unlock()
	}()

	// Keep the connection alive by reading (and discarding) client messages.
	// The web UI doesn't send meaningful messages upstream — all operations
	// go through the REST API.
	ctx := conn.CloseRead(r.Context())
	<-ctx.Done()
}

// Broadcast sends an event to all connected web UI clients.
func (h *WebUIEventHub) Broadcast(eventType string, payload interface{}) {
	data, err := json.Marshal(map[string]interface{}{
		"type":    eventType,
		"payload": payload,
	})
	if err != nil {
		return
	}

	h.mu.RLock()
	clients := make([]*websocket.Conn, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	for _, c := range clients {
		_ = c.Write(context.Background(), websocket.MessageText, data)
	}
}

// RegisterRoute registers the WebSocket endpoint on the mux.
func (h *WebUIEventHub) RegisterRoute(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/events", h.HandleWebSocket)
}
