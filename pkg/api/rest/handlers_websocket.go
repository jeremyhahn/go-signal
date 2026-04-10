package rest

import "net/http"

// handleWebSocket processes GET /v1/websocket/ and delegates to the WebSocket
// handler for authenticated messaging sessions.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	if s.wsHandler == nil {
		writeError(w, http.StatusServiceUnavailable, "websocket not configured")
		return
	}
	// If the request carries credentials, use the authenticated handler.
	// Otherwise use the unauthenticated handler (used by clients for
	// operations like fetching remote config over WebSocket transport).
	_, _, hasAuth := r.BasicAuth()
	if !hasAuth {
		// Also check query-parameter credentials (login/password).
		if r.URL.Query().Get("login") == "" {
			s.wsHandler.HandleUnauthenticated(w, r)
			return
		}
	}
	s.wsHandler.HandleAuthenticated(w, r)
}

// handleWebSocketProvisioning processes GET /v1/websocket/provisioning and
// delegates to the WebSocket handler for device provisioning sessions.
func (s *Server) handleWebSocketProvisioning(w http.ResponseWriter, r *http.Request) {
	if s.wsHandler == nil {
		writeError(w, http.StatusServiceUnavailable, "websocket not configured")
		return
	}
	s.wsHandler.HandleProvisioning(w, r)
}
