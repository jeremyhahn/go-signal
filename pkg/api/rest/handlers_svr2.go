package rest

import (
	ws "github.com/coder/websocket"
)

// wsAcceptOptions returns websocket.AcceptOptions with origin
// validation based on the server's configured allowed origins.
// InsecureSkipVerify is never set so origin checks cannot be
// bypassed.
//
// SVR2's own WebSocket endpoint moved to cmd/svr2 in Phase 4.2 per
// Java's architecture — signald only issues credentials and calls
// cmd/svr2's admin DELETE. This helper is retained for any other
// WebSocket handler (chat/messaging) that needs the same origin
// policy.
func (s *Server) wsAcceptOptions() *ws.AcceptOptions {
	if len(s.allowedOrigins) == 0 {
		return &ws.AcceptOptions{}
	}
	return &ws.AcceptOptions{
		OriginPatterns: s.allowedOrigins,
	}
}
