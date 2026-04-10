package rest

import (
	"log/slog"
	"net/http"

	ws "github.com/coder/websocket"
)

// handleSVR2WebSocket processes WebSocket upgrade requests for the SVR2
// (Secure Value Recovery v2) service. The SVR2 Noise protocol is not
// implemented; this handler accepts the WebSocket upgrade with proper origin
// validation and immediately closes with a normal closure status so that
// signal-cli can degrade gracefully without receiving a hard 404.
func (s *Server) handleSVR2WebSocket(w http.ResponseWriter, r *http.Request) {
	opts := s.wsAcceptOptions()
	conn, err := ws.Accept(w, r, opts)
	if err != nil {
		s.logger.Error("failed to accept SVR2 websocket",
			slog.String("path", r.URL.Path),
			slog.String("error", err.Error()))
		return
	}

	// Close the connection immediately with a normal closure. The SVR2 Noise
	// protocol is not implemented; this prevents signal-cli from receiving a
	// 404 and allows graceful degradation.
	if err := conn.Close(ws.StatusNormalClosure, "svr2 not implemented"); err != nil {
		slog.Debug("failed to close svr2 websocket", slog.Any("error", err))
	}
}

// wsAcceptOptions returns websocket.AcceptOptions with proper origin validation
// based on the server's configured allowed origins. InsecureSkipVerify is never
// set to ensure origin checks cannot be bypassed.
func (s *Server) wsAcceptOptions() *ws.AcceptOptions {
	if len(s.allowedOrigins) == 0 {
		return &ws.AcceptOptions{}
	}
	return &ws.AcceptOptions{
		OriginPatterns: s.allowedOrigins,
	}
}
