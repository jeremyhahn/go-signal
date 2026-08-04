//go:build desktop

package calling

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/desktop/events"
)

// noopEmitter satisfies events.Emitter and captures the most recent emit.
type noopEmitter struct {
	lastType    string
	lastPayload interface{}
}

func (e *noopEmitter) Emit(eventType string, payload interface{}) {
	e.lastType = eventType
	e.lastPayload = payload
}

func newBus() *events.Bus {
	return events.NewBus(events.NoopEmitter{})
}

// TestNewManager verifies construction.
func TestNewManager(t *testing.T) {
	t.Run("NonNilResult", func(t *testing.T) {
		m := NewManager(newBus())
		require.NotNil(t, m)
	})
	t.Run("NoActiveCallInitially", func(t *testing.T) {
		m := NewManager(newBus())
		assert.Nil(t, m.GetActiveCall())
	})
}

// TestManager_StartCall verifies call creation.
func TestManager_StartCall(t *testing.T) {
	tests := []struct {
		name      string
		peerUUID  string
		callType  CallType
		wantState CallState
	}{
		{"AudioCall", "peer-1", CallTypeAudio, CallRinging},
		{"VideoCall", "peer-2", CallTypeVideo, CallRinging},
		{"GroupAudio", "peer-3", CallTypeGroupAudio, CallRinging},
		{"GroupVideo", "peer-4", CallTypeGroupVideo, CallRinging},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(newBus())
			call, err := m.StartCall(tc.peerUUID, tc.callType)
			require.NoError(t, err)
			require.NotNil(t, call)
			assert.Equal(t, tc.peerUUID, call.PeerUUID)
			assert.Equal(t, tc.callType, call.Type)
			assert.Equal(t, tc.wantState, call.State)
			assert.NotEmpty(t, call.ID)
		})
	}
}

// TestManager_GetActiveCall verifies the active call accessor.
func TestManager_GetActiveCall(t *testing.T) {
	t.Run("NoneBeforeStart", func(t *testing.T) {
		m := NewManager(newBus())
		assert.Nil(t, m.GetActiveCall())
	})
	t.Run("ReturnedAfterStart", func(t *testing.T) {
		m := NewManager(newBus())
		call, _ := m.StartCall("peer", CallTypeAudio)
		active := m.GetActiveCall()
		require.NotNil(t, active)
		assert.Equal(t, call.ID, active.ID)
	})
}

// TestManager_AcceptCall verifies state transitions on accept.
func TestManager_AcceptCall(t *testing.T) {
	t.Run("AcceptsActiveCall", func(t *testing.T) {
		m := NewManager(newBus())
		call, _ := m.StartCall("peer", CallTypeAudio)
		err := m.AcceptCall(call.ID)
		require.NoError(t, err)
		assert.Equal(t, CallConnected, m.GetActiveCall().State)
	})
	t.Run("WrongIDIsNoop", func(t *testing.T) {
		m := NewManager(newBus())
		m.StartCall("peer", CallTypeAudio)
		err := m.AcceptCall("wrong-id")
		require.NoError(t, err)
		assert.Equal(t, CallRinging, m.GetActiveCall().State)
	})
	t.Run("NoActiveCallIsNoop", func(t *testing.T) {
		m := NewManager(newBus())
		err := m.AcceptCall("any-id")
		require.NoError(t, err)
	})
}

// TestManager_EndCall verifies that ending a call clears active state.
func TestManager_EndCall(t *testing.T) {
	t.Run("EndsActiveCall", func(t *testing.T) {
		m := NewManager(newBus())
		call, _ := m.StartCall("peer", CallTypeVideo)
		err := m.EndCall(call.ID)
		require.NoError(t, err)
		assert.Nil(t, m.GetActiveCall())
	})
	t.Run("WrongIDIsNoop", func(t *testing.T) {
		m := NewManager(newBus())
		m.StartCall("peer", CallTypeVideo)
		err := m.EndCall("wrong-id")
		require.NoError(t, err)
		assert.NotNil(t, m.GetActiveCall())
	})
	t.Run("NoActiveCallIsNoop", func(t *testing.T) {
		m := NewManager(newBus())
		err := m.EndCall("any-id")
		require.NoError(t, err)
	})
}

// TestManager_RelayOffer verifies that RelayOffer emits an event.
func TestManager_RelayOffer(t *testing.T) {
	t.Run("EmitsEvent", func(t *testing.T) {
		captured := &noopEmitter{}
		bus := events.NewBus(captured)
		m := NewManager(bus)
		offer := CallOffer{CallID: "c1", SDP: "v=0"}
		err := m.RelayOffer(offer)
		require.NoError(t, err)
		assert.Equal(t, "signal:call:offer", captured.lastType)
		assert.Equal(t, offer, captured.lastPayload)
	})
	t.Run("EmptyOffer", func(t *testing.T) {
		m := NewManager(newBus())
		err := m.RelayOffer(CallOffer{})
		require.NoError(t, err)
	})
}

// TestManager_RelayAnswer verifies that RelayAnswer always returns nil.
func TestManager_RelayAnswer(t *testing.T) {
	t.Run("ReturnsNil", func(t *testing.T) {
		m := NewManager(newBus())
		err := m.RelayAnswer(CallAnswer{CallID: "c1", SDP: "v=0"})
		require.NoError(t, err)
	})
	t.Run("EmptyAnswer", func(t *testing.T) {
		m := NewManager(newBus())
		err := m.RelayAnswer(CallAnswer{})
		require.NoError(t, err)
	})
}

// TestManager_RelayICECandidate verifies that RelayICECandidate returns nil.
func TestManager_RelayICECandidate(t *testing.T) {
	t.Run("ReturnsNil", func(t *testing.T) {
		m := NewManager(newBus())
		err := m.RelayICECandidate(IceCandidate{CallID: "c1", Candidate: "cand"})
		require.NoError(t, err)
	})
	t.Run("EmptyCandidate", func(t *testing.T) {
		m := NewManager(newBus())
		err := m.RelayICECandidate(IceCandidate{})
		require.NoError(t, err)
	})
}

// TestGenerateCallID verifies that generated IDs are non-empty and unique.
func TestGenerateCallID(t *testing.T) {
	t.Run("NonEmpty", func(t *testing.T) {
		id := generateCallID()
		assert.NotEmpty(t, id)
	})
	t.Run("UniquenessOverTime", func(t *testing.T) {
		id1 := generateCallID()
		time.Sleep(time.Nanosecond)
		id2 := generateCallID()
		assert.NotEqual(t, id1, id2)
	})
}

// TestCallTypes verifies the declared constant values.
func TestCallTypes(t *testing.T) {
	assert.Equal(t, CallType(1), CallTypeAudio)
	assert.Equal(t, CallType(2), CallTypeVideo)
	assert.Equal(t, CallType(3), CallTypeGroupAudio)
	assert.Equal(t, CallType(4), CallTypeGroupVideo)
}

// TestCallStates verifies the declared state constant values.
func TestCallStates(t *testing.T) {
	assert.Equal(t, CallState(0), CallIdle)
	assert.Equal(t, CallState(1), CallRinging)
	assert.Equal(t, CallState(2), CallConnected)
	assert.Equal(t, CallState(3), CallEnded)
}
