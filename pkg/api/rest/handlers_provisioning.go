package rest

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/messages"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
)

// handleSendProvisioningMessage processes PUT /v1/provisioning/{destination}
// and forwards the provisioning message to the waiting provisioning WebSocket
// session.
func (s *Server) handleSendProvisioningMessage(w http.ResponseWriter, r *http.Request) {
	destination := r.PathValue("destination")
	if destination == "" {
		writeError(w, http.StatusBadRequest, "missing destination")
		return
	}

	var req ProvisioningMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Attempt delivery to an active provisioning WebSocket session.
	// Provisioning sessions are registered with deviceID 0.
	if s.wsSessions != nil {
		envelope := &messages.Envelope{
			ServerGUID: destination,
		}

		msg := &signalws.WebSocketMessage{
			Type: "request",
			Request: &signalws.WebSocketRequest{
				ID:   1,
				Verb: "PUT",
				Path: "/v1/message",
				Body: req.Body,
			},
		}

		session := s.wsSessions.GetSession(destination, 0)
		if session != nil {
			if err := session.Send(msg); err != nil {
				s.logger.Warn("failed to deliver provisioning message",
					slog.String("destination", destination),
					slog.String("error", err.Error()))
			}
			_ = envelope // suppress unused warning
		}
	}

	w.WriteHeader(http.StatusNoContent)
}
