package calling

import "encoding/json"

// CallSignalType identifies the kind of call signaling message.
type CallSignalType string

const (
	// SignalTypeOffer is an SDP offer from the caller to the callee.
	SignalTypeOffer CallSignalType = "offer"

	// SignalTypeAnswer is an SDP answer from the callee back to the caller.
	SignalTypeAnswer CallSignalType = "answer"

	// SignalTypeICE carries an ICE candidate from either peer.
	SignalTypeICE CallSignalType = "ice"

	// SignalTypeHangup signals that a peer has ended the call.
	SignalTypeHangup CallSignalType = "hangup"
)

// CallSignalMessage is the wire envelope for a single call signaling event.
// The Payload field carries the SDP or ICE candidate as raw JSON so that the
// server can relay it without deserializing media-specific structures.
type CallSignalMessage struct {
	Type       CallSignalType  `json:"type"`
	CallID     string          `json:"callId"`
	CallerUUID string          `json:"callerUuid"`
	CalleeUUID string          `json:"calleeUuid"`
	CallType   string          `json:"callType"`
	Payload    json.RawMessage `json:"payload"`
}
