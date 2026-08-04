package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/calling"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

func testCallLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// buildCallingService constructs a callSignalingService backed by an in-memory
// SessionManager and a no-op CallingManager.
func buildCallingService() (CallSignalingService, *signalws.SessionManager) {
	sessions := signalws.NewSessionManager(testCallLogger())
	callingMgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider:    &noOpTurnProvider{},
		SurveyPublisher: &noOpSurveyPublisher{},
		Logger:          testCallLogger(),
	})
	svc := NewCallSignalingService(sessions, callingMgr, testCallLogger())
	return svc, sessions
}

// registerSession creates a Session with a nil conn (send-only, no real WS
// connection) and registers it with mgr. The session is returned so callers
// can drain its internal send channel to verify delivery.
func registerSession(mgr *signalws.SessionManager, uuid string, deviceID uint64) *signalws.Session {
	s := signalws.NewSession(nil, uuid, deviceID, nil, testCallLogger())
	mgr.Register(s)
	return s
}

// callMsg builds a minimal CallSignalMessage for tests.
func callMsg(typ calling.CallSignalType, callerUUID, calleeUUID string) *calling.CallSignalMessage {
	return &calling.CallSignalMessage{
		Type:       typ,
		CallID:     "call-id-1",
		CallerUUID: callerUUID,
		CalleeUUID: calleeUUID,
		CallType:   "audio",
		Payload:    json.RawMessage(`{"sdp":"test"}`),
	}
}

// ─── NewCallSignalingService ─────────────────────────────────────────────────

func TestNewCallSignalingService_ReturnsNonNil(t *testing.T) {
	svc, _ := buildCallingService()
	require.NotNil(t, svc)
}

func TestNewCallSignalingService_ImplementsInterface(t *testing.T) {
	svc, _ := buildCallingService()
	// Verify the returned concrete type satisfies the interface.
	iface := CallSignalingService(svc)
	if iface == nil {
		t.Fatal("expected non-nil service")
	}
}

// ─── GetTURNCredentials ───────────────────────────────────────────────────────

func TestCallSignalingService_GetTURNCredentials_Success(t *testing.T) {
	svc, _ := buildCallingService()
	ctx := context.Background()

	resp, err := svc.GetTURNCredentials(ctx)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Len(t, resp.Relays, 1)
}

func TestCallSignalingService_GetTURNCredentials_ProviderError(t *testing.T) {
	sessions := signalws.NewSessionManager(testCallLogger())
	callingMgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider:    &failingTurnProvider{err: errors.New("turn server unavailable")},
		SurveyPublisher: &noOpSurveyPublisher{},
		Logger:          testCallLogger(),
	})
	svc := NewCallSignalingService(sessions, callingMgr, testCallLogger())

	_, err := svc.GetTURNCredentials(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "turn server unavailable")
}

// ─── RelayOffer ──────────────────────────────────────────────────────────────

func TestCallSignalingService_RelayOffer_PeerConnected(t *testing.T) {
	svc, sessions := buildCallingService()
	ctx := context.Background()

	callee := registerSession(sessions, "callee-uuid", 1)
	msg := callMsg(calling.SignalTypeOffer, "caller-uuid", "callee-uuid")

	err := svc.RelayOffer(ctx, "caller-uuid", msg)
	require.NoError(t, err)

	// Verify the callee's session is still open (not closed by the relay).
	select {
	case <-callee.Done():
		t.Error("callee session should not be closed after relay")
	default:
		// Expected: session is still open.
	}
	_ = callee
}

// TestCallSignalingService_RelayOffer_NoPeer verifies that RelayOffer returns
// a PeerNotConnectedError when the callee has no active session.
func TestCallSignalingService_RelayOffer_NoPeer(t *testing.T) {
	svc, _ := buildCallingService()
	ctx := context.Background()

	msg := callMsg(calling.SignalTypeOffer, "caller-uuid", "callee-uuid-absent")

	err := svc.RelayOffer(ctx, "caller-uuid", msg)
	require.Error(t, err)

	var pnc *calling.PeerNotConnectedError
	require.True(t, errors.As(err, &pnc))
	assert.Equal(t, "callee-uuid-absent", pnc.UUID)
}

// ─── RelayAnswer ─────────────────────────────────────────────────────────────

func TestCallSignalingService_RelayAnswer_PeerConnected(t *testing.T) {
	svc, sessions := buildCallingService()
	ctx := context.Background()

	registerSession(sessions, "caller-uuid", 1)
	msg := callMsg(calling.SignalTypeAnswer, "caller-uuid", "callee-uuid")

	err := svc.RelayAnswer(ctx, "callee-uuid", msg)
	require.NoError(t, err)
}

func TestCallSignalingService_RelayAnswer_NoPeer(t *testing.T) {
	svc, _ := buildCallingService()
	ctx := context.Background()

	msg := callMsg(calling.SignalTypeAnswer, "caller-uuid-absent", "callee-uuid")

	err := svc.RelayAnswer(ctx, "callee-uuid", msg)
	require.Error(t, err)

	var pnc *calling.PeerNotConnectedError
	require.True(t, errors.As(err, &pnc))
	assert.Equal(t, "caller-uuid-absent", pnc.UUID)
}

// ─── RelayICECandidate ────────────────────────────────────────────────────────

// TestCallSignalingService_RelayICE_SenderIsCaller verifies that when the sender
// is the caller, the ICE candidate is delivered to the callee.
func TestCallSignalingService_RelayICE_SenderIsCaller(t *testing.T) {
	svc, sessions := buildCallingService()
	ctx := context.Background()

	registerSession(sessions, "callee-uuid", 1)
	msg := callMsg(calling.SignalTypeICE, "caller-uuid", "callee-uuid")

	err := svc.RelayICECandidate(ctx, "caller-uuid", msg)
	require.NoError(t, err)
}

// TestCallSignalingService_RelayICE_SenderIsCallee verifies that when the
// sender is the callee, the ICE candidate is delivered to the caller.
func TestCallSignalingService_RelayICE_SenderIsCallee(t *testing.T) {
	svc, sessions := buildCallingService()
	ctx := context.Background()

	registerSession(sessions, "caller-uuid", 1)
	msg := callMsg(calling.SignalTypeICE, "caller-uuid", "callee-uuid")

	err := svc.RelayICECandidate(ctx, "callee-uuid", msg)
	require.NoError(t, err)
}

func TestCallSignalingService_RelayICE_NoPeer(t *testing.T) {
	svc, _ := buildCallingService()
	ctx := context.Background()

	msg := callMsg(calling.SignalTypeICE, "caller-uuid", "callee-uuid-absent")

	err := svc.RelayICECandidate(ctx, "caller-uuid", msg)
	require.Error(t, err)

	var pnc *calling.PeerNotConnectedError
	require.True(t, errors.As(err, &pnc))
}

// ─── RelayHangup ─────────────────────────────────────────────────────────────

func TestCallSignalingService_RelayHangup_CallerHangsUp(t *testing.T) {
	svc, sessions := buildCallingService()
	ctx := context.Background()

	registerSession(sessions, "callee-uuid", 1)
	msg := callMsg(calling.SignalTypeHangup, "caller-uuid", "callee-uuid")

	err := svc.RelayHangup(ctx, "caller-uuid", msg)
	require.NoError(t, err)
}

func TestCallSignalingService_RelayHangup_CalleeHangsUp(t *testing.T) {
	svc, sessions := buildCallingService()
	ctx := context.Background()

	registerSession(sessions, "caller-uuid", 1)
	msg := callMsg(calling.SignalTypeHangup, "caller-uuid", "callee-uuid")

	err := svc.RelayHangup(ctx, "callee-uuid", msg)
	require.NoError(t, err)
}

func TestCallSignalingService_RelayHangup_NoPeer(t *testing.T) {
	svc, _ := buildCallingService()
	ctx := context.Background()

	msg := callMsg(calling.SignalTypeHangup, "caller-uuid-absent", "callee-uuid")

	err := svc.RelayHangup(ctx, "callee-uuid", msg)
	require.Error(t, err)

	var pnc *calling.PeerNotConnectedError
	require.True(t, errors.As(err, &pnc))
}

// ─── sendToAccount — session closed path ─────────────────────────────────────

// TestCallSignalingService_RelayOffer_SessionClosed exercises the
// sendToAccount path where the session exists but is closed (Send returns an
// error), which maps to PeerNotConnectedError.
func TestCallSignalingService_RelayOffer_SessionClosed(t *testing.T) {
	svc, sessions := buildCallingService()
	ctx := context.Background()

	callee := registerSession(sessions, "callee-closed", 1)
	// Close the session's done channel to simulate a disconnected client.
	callee.Close()

	msg := callMsg(calling.SignalTypeOffer, "caller-uuid", "callee-closed")

	err := svc.RelayOffer(ctx, "caller-uuid", msg)
	require.Error(t, err)

	var pnc *calling.PeerNotConnectedError
	require.True(t, errors.As(err, &pnc))
	assert.Equal(t, "callee-closed", pnc.UUID)
}

// ─── encodeCallSignalBody ─────────────────────────────────────────────────────

func TestEncodeCallSignalBody_RoundTrip(t *testing.T) {
	msg := &calling.CallSignalMessage{
		Type:       calling.SignalTypeOffer,
		CallID:     "cid",
		CallerUUID: "caller",
		CalleeUUID: "callee",
		CallType:   "video",
		Payload:    json.RawMessage(`{"sdp":"v=0"}`),
	}

	encoded, err := encodeCallSignalBody(msg)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// Verify it is valid base64 that decodes to valid JSON.
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)

	var out calling.CallSignalMessage
	require.NoError(t, json.Unmarshal(decoded, &out))
	assert.Equal(t, calling.SignalTypeOffer, out.Type)
	assert.Equal(t, "cid", out.CallID)
	assert.Equal(t, "caller", out.CallerUUID)
	assert.Equal(t, "callee", out.CalleeUUID)
}

// ─── oppositeUUID ─────────────────────────────────────────────────────────────

func TestOppositeUUID_SenderIsCaller(t *testing.T) {
	msg := &calling.CallSignalMessage{
		CallerUUID: "caller",
		CalleeUUID: "callee",
	}
	assert.Equal(t, "callee", oppositeUUID("caller", msg))
}

func TestOppositeUUID_SenderIsCallee(t *testing.T) {
	msg := &calling.CallSignalMessage{
		CallerUUID: "caller",
		CalleeUUID: "callee",
	}
	assert.Equal(t, "caller", oppositeUUID("callee", msg))
}

func TestOppositeUUID_SenderIsUnknown(t *testing.T) {
	// Any sender UUID that is not the caller returns the caller UUID.
	msg := &calling.CallSignalMessage{
		CallerUUID: "caller",
		CalleeUUID: "callee",
	}
	assert.Equal(t, "caller", oppositeUUID("unknown-uuid", msg))
}

// ─── relayDispatch map coverage ───────────────────────────────────────────────

func TestRelayDispatch_ContainsAllSignalTypes(t *testing.T) {
	expectedTypes := []calling.CallSignalType{
		calling.SignalTypeOffer,
		calling.SignalTypeAnswer,
		calling.SignalTypeICE,
		calling.SignalTypeHangup,
	}
	for _, typ := range expectedTypes {
		_, ok := relayDispatch[typ]
		assert.True(t, ok, "relayDispatch missing entry for %q", typ)
	}
}

// ─── requestID monotonicity ───────────────────────────────────────────────────

// TestCallSignalingService_RequestIDMonotonicity verifies that successive relay
// calls produce strictly increasing WebSocket request IDs.
func TestCallSignalingService_RequestIDMonotonicity(t *testing.T) {
	svc, sessions := buildCallingService()
	ctx := context.Background()

	concrete := svc.(*callSignalingService)

	registerSession(sessions, "callee-uuid", 1)
	msg := callMsg(calling.SignalTypeOffer, "caller-uuid", "callee-uuid")

	before := concrete.requestID.Load()
	require.NoError(t, svc.RelayOffer(ctx, "caller-uuid", msg))
	after := concrete.requestID.Load()

	assert.Greater(t, after, before, "requestID should increase after relay")
}

// ─── Stubs ────────────────────────────────────────────────────────────────────

// failingTurnProvider returns a configurable error from RetrieveCredentials.
type failingTurnProvider struct {
	err error
}

func (p *failingTurnProvider) RetrieveCredentials(_ context.Context) (*calling.TurnToken, error) {
	return nil, p.err
}
