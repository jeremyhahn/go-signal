package rest

import (
	ws "github.com/coder/websocket"
)

// wsAcceptOptions returns websocket.AcceptOptions validating origins against the configured allowed origins; InsecureSkipVerify is never set.
func (s *Server) wsAcceptOptions() *ws.AcceptOptions {
	if len(s.allowedOrigins) == 0 {
		return &ws.AcceptOptions{}
	}
	return &ws.AcceptOptions{
		OriginPatterns: s.allowedOrigins,
	}
}
