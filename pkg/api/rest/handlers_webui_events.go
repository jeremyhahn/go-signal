package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// broadcastWriteTimeout bounds each per-client WebSocket write so that one
// stalled (backpressured) browser cannot block the entire broadcast loop.
const broadcastWriteTimeout = 5 * time.Second

// WebUIEventHub manages WebSocket connections for the web UI.
// When the SDK client receives messages via its WebSocket to the Signal
// server, events are broadcast to all connected web UI browsers.
type WebUIEventHub struct {
	mu      sync.RWMutex
	clients map[*websocket.Conn]struct{}
	// broadcastMu serializes Broadcast so two concurrent broadcasts never
	// issue overlapping writes on the same connection (coder/websocket
	// forbids concurrent writes to one Conn).
	broadcastMu sync.Mutex
	// allowedOrigins lists Origin patterns permitted to open the event
	// WebSocket. When empty the coder/websocket default applies, which
	// requires the Origin host to match the request Host (same-origin) —
	// InsecureSkipVerify is never set, so cross-site hijacking is rejected.
	allowedOrigins []string
}

// NewWebUIEventHub creates an event hub for web UI clients.
func NewWebUIEventHub() *WebUIEventHub {
	return &WebUIEventHub{
		clients: make(map[*websocket.Conn]struct{}),
	}
}

// SetAllowedOrigins configures the Origin patterns permitted to open the event
// WebSocket. Passing an empty slice keeps the secure same-origin default.
func (h *WebUIEventHub) SetAllowedOrigins(origins []string) {
	h.mu.Lock()
	h.allowedOrigins = origins
	h.mu.Unlock()
}

// acceptOptions returns origin-restricted WebSocket accept options. It never
// sets InsecureSkipVerify, mirroring the server's wsAcceptOptions policy.
func (h *WebUIEventHub) acceptOptions() *websocket.AcceptOptions {
	h.mu.RLock()
	origins := h.allowedOrigins
	h.mu.RUnlock()
	if len(origins) == 0 {
		return &websocket.AcceptOptions{}
	}
	return &websocket.AcceptOptions{OriginPatterns: origins}
}

// HandleWebSocket upgrades the HTTP connection to WebSocket and registers
// the client for event delivery. The connection is held open until the
// client disconnects or the server shuts down.
func (h *WebUIEventHub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, h.acceptOptions())
	if err != nil {
		return
	}
	defer func() { _ = conn.CloseNow() }()

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

	// Serialize the write phase so concurrent broadcasts can't write the same
	// connection at once.
	h.broadcastMu.Lock()
	defer h.broadcastMu.Unlock()

	h.mu.RLock()
	clients := make([]*websocket.Conn, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()

	var failed []*websocket.Conn
	for _, c := range clients {
		ctx, cancel := context.WithTimeout(context.Background(), broadcastWriteTimeout)
		err := c.Write(ctx, websocket.MessageText, data)
		cancel()
		if err != nil {
			failed = append(failed, c)
		}
	}

	// Reap connections that errored (closed or stalled) so a dead client is
	// not retained and retried on every subsequent broadcast.
	if len(failed) > 0 {
		h.mu.Lock()
		for _, c := range failed {
			delete(h.clients, c)
		}
		h.mu.Unlock()
		for _, c := range failed {
			_ = c.CloseNow()
		}
	}
}

// RegisterRoute registers the WebSocket endpoint on the mux.
func (h *WebUIEventHub) RegisterRoute(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/events", h.HandleWebSocket)
}
