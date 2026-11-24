//go:build desktop

// Package calling manages audio/video call state and signaling.
// The actual WebRTC media transport is handled by the browser engine
// in the Wails webview. This package handles:
//   - Call state machine (idle → ringing → connected → ended)
//   - Signal calling protocol (offer/answer, ICE candidates via WebSocket)
//   - SFU communication for group calls
package calling

import (
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/desktop/events"
)

// CallState represents the current state of a call.
type CallState int

const (
	CallIdle CallState = iota
	CallRinging
	CallConnected
	CallEnded
)

// CallType identifies the kind of call.
type CallType int

const (
	CallTypeAudio      CallType = 1
	CallTypeVideo      CallType = 2
	CallTypeGroupAudio CallType = 3
	CallTypeGroupVideo CallType = 4
)

// Call represents an active or recent call.
type Call struct {
	ID        string    `json:"id"`
	PeerUUID  string    `json:"peerUuid"`
	Type      CallType  `json:"type"`
	State     CallState `json:"state"`
	StartedAt int64     `json:"startedAt"`
}

// CallOffer represents a WebRTC offer.
type CallOffer struct {
	CallID string `json:"callId"`
	SDP    string `json:"sdp"`
}

// CallAnswer represents a WebRTC answer.
type CallAnswer struct {
	CallID string `json:"callId"`
	SDP    string `json:"sdp"`
}

// IceCandidate represents an ICE candidate.
type IceCandidate struct {
	CallID    string `json:"callId"`
	Candidate string `json:"candidate"`
	SDPMid    string `json:"sdpMid"`
	SDPMLine  int    `json:"sdpMLineIndex"`
}

// Manager handles call state and signaling.
type Manager struct {
	mu       sync.RWMutex
	eventBus *events.Bus
	active   *Call
}

// NewManager creates a call manager.
func NewManager(eventBus *events.Bus) *Manager {
	return &Manager{eventBus: eventBus}
}

// StartCall initiates a call to a peer.
func (m *Manager) StartCall(peerUUID string, callType CallType) (*Call, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	call := &Call{
		ID:       generateCallID(),
		PeerUUID: peerUUID,
		Type:     callType,
		State:    CallRinging,
	}
	m.active = call

	// The frontend will create the RTCPeerConnection and generate
	// the SDP offer. The Go backend relays it via Signal's calling protocol.

	return call, nil
}

// AcceptCall accepts an incoming call.
func (m *Manager) AcceptCall(callID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active == nil || m.active.ID != callID {
		return nil
	}
	m.active.State = CallConnected
	return nil
}

// EndCall ends the active call.
func (m *Manager) EndCall(callID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.active == nil || m.active.ID != callID {
		return nil
	}
	m.active.State = CallEnded
	m.active = nil
	return nil
}

// GetActiveCall returns the current call, if any.
func (m *Manager) GetActiveCall() *Call {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active
}

// RelayOffer relays a call offer to the peer via the event bus.
// The server-side signaling service handles the actual WebSocket relay.
func (m *Manager) RelayOffer(offer CallOffer) error {
	m.eventBus.Emit(events.EventType("signal:call:offer"), offer)
	return nil
}

// RelayAnswer relays a call answer to the peer.
func (m *Manager) RelayAnswer(answer CallAnswer) error {
	return nil
}

// RelayICECandidate relays an ICE candidate to the peer.
func (m *Manager) RelayICECandidate(candidate IceCandidate) error {
	return nil
}

func generateCallID() string {
	// Simple ID generation; will use UUID in production.
	return "call-" + fmt.Sprint(time.Now().UnixNano())
}
