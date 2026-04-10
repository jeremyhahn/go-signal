package rest

import (
	"encoding/json"
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/service"
)

// handleCallOffer handles POST /v1/call/offer. It decodes a CallSignalMessage
// from the request body, sets the authenticated account's UUID as CallerUUID,
// and relays the SDP offer to the callee via the signaling service.
func (s *Server) handleCallOffer(w http.ResponseWriter, r *http.Request) {
	s.relayCallSignal(w, r, func(svc service.CallSignalingService, senderUUID string, msg *calling.CallSignalMessage) error {
		msg.CallerUUID = senderUUID
		return svc.RelayOffer(r.Context(), senderUUID, msg)
	})
}

// handleCallAnswer handles POST /v1/call/answer. It decodes a CallSignalMessage,
// sets the authenticated account's UUID as CalleeUUID, and relays the SDP answer
// to the caller via the signaling service.
func (s *Server) handleCallAnswer(w http.ResponseWriter, r *http.Request) {
	s.relayCallSignal(w, r, func(svc service.CallSignalingService, senderUUID string, msg *calling.CallSignalMessage) error {
		msg.CalleeUUID = senderUUID
		return svc.RelayAnswer(r.Context(), senderUUID, msg)
	})
}

// handleCallICE handles POST /v1/call/ice. It decodes a CallSignalMessage and
// relays the ICE candidate to the opposite peer via the signaling service.
func (s *Server) handleCallICE(w http.ResponseWriter, r *http.Request) {
	s.relayCallSignal(w, r, func(svc service.CallSignalingService, senderUUID string, msg *calling.CallSignalMessage) error {
		return svc.RelayICECandidate(r.Context(), senderUUID, msg)
	})
}

// handleCallHangup handles POST /v1/call/hangup. It decodes a CallSignalMessage
// and notifies the opposite peer that the call has ended.
func (s *Server) handleCallHangup(w http.ResponseWriter, r *http.Request) {
	s.relayCallSignal(w, r, func(svc service.CallSignalingService, senderUUID string, msg *calling.CallSignalMessage) error {
		return svc.RelayHangup(r.Context(), senderUUID, msg)
	})
}

// signalRelayFn is the per-handler dispatch function passed to relayCallSignal.
type signalRelayFn func(svc service.CallSignalingService, senderUUID string, msg *calling.CallSignalMessage) error

// relayCallSignal is the shared implementation for all four call signaling
// handlers. It authenticates the request, decodes the body, and delegates to fn.
// Responses:
//   - 401 — no authenticated account in context
//   - 400 — malformed JSON body or InvalidCallSignalError
//   - 404 — PeerNotConnectedError
//   - 204 — signal relayed successfully
func (s *Server) relayCallSignal(w http.ResponseWriter, r *http.Request, fn signalRelayFn) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var msg calling.CallSignalMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := fn(s.callSignaling, acct.UUID, &msg); err != nil {
		switch err.(type) {
		case *calling.PeerNotConnectedError:
			writeError(w, http.StatusNotFound, "peer not connected")
		case *calling.InvalidCallSignalError:
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			s.logger.Error("failed to relay call signal", "error", err.Error())
			writeError(w, http.StatusInternalServerError, "internal server error")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
