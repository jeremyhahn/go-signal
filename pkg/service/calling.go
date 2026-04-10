package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-signal/pkg/calling"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
)

// CallSignalingService relays WebRTC signaling messages between peers over
// their active WebSocket sessions. All media negotiation is fully peer-to-peer;
// the server is a pure relay and never inspects SDP or ICE content.
type CallSignalingService interface {
	// RelayOffer forwards an SDP offer from the caller to the callee.
	RelayOffer(ctx context.Context, callerUUID string, msg *calling.CallSignalMessage) error

	// RelayAnswer forwards an SDP answer from the callee back to the caller.
	RelayAnswer(ctx context.Context, calleeUUID string, msg *calling.CallSignalMessage) error

	// RelayICECandidate forwards an ICE candidate from either peer to the opposite peer.
	RelayICECandidate(ctx context.Context, senderUUID string, msg *calling.CallSignalMessage) error

	// RelayHangup notifies the opposite peer that this peer has ended the call.
	RelayHangup(ctx context.Context, senderUUID string, msg *calling.CallSignalMessage) error

	// GetTURNCredentials returns the TURN relay servers required for call setup.
	GetTURNCredentials(ctx context.Context) (*calling.GetCallingRelaysResponse, error)
}

// callSignalingService is the production implementation of CallSignalingService.
type callSignalingService struct {
	sessions *signalws.SessionManager
	calling  *calling.CallingManager
	logger   *slog.Logger

	// requestID is a monotonically increasing counter used to generate unique
	// WebSocketRequest IDs for server-pushed call signal messages.
	requestID atomic.Uint64
}

// relayFunc is the signature used in the map-based signal dispatch table.
type relayFunc func(svc *callSignalingService, ctx context.Context, senderUUID string, msg *calling.CallSignalMessage) error

// relayDispatch maps each CallSignalType to its relay implementation. This
// avoids a switch statement and satisfies the project's map-dispatch convention.
var relayDispatch = map[calling.CallSignalType]relayFunc{
	calling.SignalTypeOffer:  (*callSignalingService).relayOffer,
	calling.SignalTypeAnswer: (*callSignalingService).relayAnswer,
	calling.SignalTypeICE:    (*callSignalingService).relayICE,
	calling.SignalTypeHangup: (*callSignalingService).relayHangup,
}

// NewCallSignalingService constructs a callSignalingService. Both sessions and
// callingMgr must be non-nil.
func NewCallSignalingService(
	sessions *signalws.SessionManager,
	callingMgr *calling.CallingManager,
	logger *slog.Logger,
) CallSignalingService {
	return &callSignalingService{
		sessions: sessions,
		calling:  callingMgr,
		logger:   logger.With(slog.String("service", "call-signaling")),
	}
}

// RelayOffer implements CallSignalingService.
func (s *callSignalingService) RelayOffer(ctx context.Context, callerUUID string, msg *calling.CallSignalMessage) error {
	return s.relayOffer(ctx, callerUUID, msg)
}

// RelayAnswer implements CallSignalingService.
func (s *callSignalingService) RelayAnswer(ctx context.Context, calleeUUID string, msg *calling.CallSignalMessage) error {
	return s.relayAnswer(ctx, calleeUUID, msg)
}

// RelayICECandidate implements CallSignalingService.
func (s *callSignalingService) RelayICECandidate(ctx context.Context, senderUUID string, msg *calling.CallSignalMessage) error {
	return s.relayICE(ctx, senderUUID, msg)
}

// RelayHangup implements CallSignalingService.
func (s *callSignalingService) RelayHangup(ctx context.Context, senderUUID string, msg *calling.CallSignalMessage) error {
	return s.relayHangup(ctx, senderUUID, msg)
}

// GetTURNCredentials implements CallSignalingService.
func (s *callSignalingService) GetTURNCredentials(ctx context.Context) (*calling.GetCallingRelaysResponse, error) {
	return s.calling.GetCallingRelays(ctx)
}

// relayOffer sends an SDP offer to the callee's primary device (device 1).
func (s *callSignalingService) relayOffer(ctx context.Context, _ string, msg *calling.CallSignalMessage) error {
	return s.sendToAccount(ctx, msg.CalleeUUID, msg)
}

// relayAnswer sends an SDP answer to the caller's primary device (device 1).
func (s *callSignalingService) relayAnswer(ctx context.Context, _ string, msg *calling.CallSignalMessage) error {
	return s.sendToAccount(ctx, msg.CallerUUID, msg)
}

// relayICE sends an ICE candidate to the opposite peer.
// If the sender is the caller, the candidate goes to the callee and vice versa.
func (s *callSignalingService) relayICE(ctx context.Context, senderUUID string, msg *calling.CallSignalMessage) error {
	target := oppositeUUID(senderUUID, msg)
	return s.sendToAccount(ctx, target, msg)
}

// relayHangup notifies the opposite peer that the call has ended.
func (s *callSignalingService) relayHangup(ctx context.Context, senderUUID string, msg *calling.CallSignalMessage) error {
	target := oppositeUUID(senderUUID, msg)
	return s.sendToAccount(ctx, target, msg)
}

// oppositeUUID returns the UUID of the peer that is not the sender.
// If senderUUID matches the caller, the callee is returned, and vice versa.
func oppositeUUID(senderUUID string, msg *calling.CallSignalMessage) string {
	if senderUUID == msg.CallerUUID {
		return msg.CalleeUUID
	}
	return msg.CallerUUID
}

// sendToAccount looks up the primary session (device 1) for peerUUID and
// delivers msg as a WebSocket push request. Returns PeerNotConnectedError when
// no session exists.
func (s *callSignalingService) sendToAccount(ctx context.Context, peerUUID string, msg *calling.CallSignalMessage) error {
	// Signal clients connect on device 1 (the primary device). For signaling
	// purposes we target device 1 only; multi-device fan-out is not required
	// for 1:1 call signaling.
	const primaryDevice uint64 = 1

	session := s.sessions.GetSession(peerUUID, primaryDevice)
	if session == nil {
		s.logger.DebugContext(ctx, "peer has no active websocket session",
			slog.String("peerUUID", peerUUID),
			slog.String("callId", msg.CallID),
			slog.String("signalType", string(msg.Type)),
		)
		return &calling.PeerNotConnectedError{UUID: peerUUID}
	}

	body, err := encodeCallSignalBody(msg)
	if err != nil {
		return &calling.InvalidCallSignalError{Message: "failed to marshal call signal: " + err.Error()}
	}

	wsMsg := &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   s.requestID.Add(1),
			Verb: "PUT",
			Path: "/api/v1/call/signal",
			Body: body,
		},
	}

	if err := session.Send(wsMsg); err != nil {
		s.logger.WarnContext(ctx, "failed to relay call signal",
			slog.String("peerUUID", peerUUID),
			slog.String("callId", msg.CallID),
			slog.String("signalType", string(msg.Type)),
			slog.String("error", err.Error()),
		)
		return &calling.PeerNotConnectedError{UUID: peerUUID}
	}

	s.logger.DebugContext(ctx, "relayed call signal",
		slog.String("peerUUID", peerUUID),
		slog.String("callId", msg.CallID),
		slog.String("signalType", string(msg.Type)),
	)

	return nil
}

// encodeCallSignalBody serializes msg as JSON and base64-encodes the result
// for use as a WebSocketRequest body field, matching the encoding used by
// encodeEnvelopeBody in the websocket package.
func encodeCallSignalBody(msg *calling.CallSignalMessage) (string, error) {
	data, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// Ensure relayDispatch entries are exercised through the exported interface so
// that unused-variable linters do not flag the map. The map is consumed by
// handler-level dispatch in handlers_call_signaling.go.
var _ = relayDispatch
