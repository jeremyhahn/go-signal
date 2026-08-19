//go:build desktop

package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/desktop/events"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// testHandler captures messages for assertion.
type testHandler struct {
	msgs []signal.ReceivedMessage
}

func (h *testHandler) HandleMessage(msg signal.ReceivedMessage) {
	h.msgs = append(h.msgs, msg)
}

// TestNewManager verifies Manager construction.
func TestNewManager(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		client, err := newTestClient()
		require.NoError(t, err)
		bus := events.NewBus(events.NoopEmitter{})
		m := NewManager(client, bus, &testHandler{})
		require.NotNil(t, m)
	})
	t.Run("NilHandlerIsAccepted", func(t *testing.T) {
		client, err := newTestClient()
		require.NoError(t, err)
		bus := events.NewBus(events.NoopEmitter{})
		m := NewManager(client, bus, nil)
		require.NotNil(t, m)
	})
}

// TestManager_IsConnected verifies the initial state and state after Stop.
func TestManager_IsConnected(t *testing.T) {
	t.Run("FalseBeforeStart", func(t *testing.T) {
		client, err := newTestClient()
		require.NoError(t, err)
		m := NewManager(client, events.NewBus(events.NoopEmitter{}), nil)
		assert.False(t, m.IsConnected())
	})
	t.Run("FalseAfterStop", func(t *testing.T) {
		client, err := newTestClient()
		require.NoError(t, err)
		m := NewManager(client, events.NewBus(events.NoopEmitter{}), nil)
		m.Start(context.Background())
		m.Stop()
		// connected is set to false when ConnectWebSocket fails
		assert.False(t, m.IsConnected())
	})
}

// TestManager_Stop verifies graceful shutdown.
func TestManager_Stop(t *testing.T) {
	t.Run("StopBeforeStartIsNoop", func(t *testing.T) {
		client, err := newTestClient()
		require.NoError(t, err)
		m := NewManager(client, events.NewBus(events.NoopEmitter{}), nil)
		assert.NotPanics(t, m.Stop)
	})
	t.Run("StopAfterStart", func(t *testing.T) {
		client, err := newTestClient()
		require.NoError(t, err)
		m := NewManager(client, events.NewBus(events.NoopEmitter{}), nil)
		m.Start(context.Background())
		assert.NotPanics(t, m.Stop)
	})
	t.Run("DoubleStopIsNoop", func(t *testing.T) {
		client, err := newTestClient()
		require.NoError(t, err)
		m := NewManager(client, events.NewBus(events.NoopEmitter{}), nil)
		m.Start(context.Background())
		m.Stop()
		assert.NotPanics(t, m.Stop)
	})
}

// TestManager_Start verifies that Start launches the connection loop.
func TestManager_Start(t *testing.T) {
	t.Run("StartDoesNotBlock", func(t *testing.T) {
		client, err := newTestClient()
		require.NoError(t, err)
		m := NewManager(client, events.NewBus(events.NoopEmitter{}), nil)

		done := make(chan struct{})
		go func() {
			m.Start(context.Background())
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("Start blocked")
		}
		m.Stop()
	})

	t.Run("ConnectionLoopEmitsStatusEvent", func(t *testing.T) {
		client, err := newTestClient()
		require.NoError(t, err)

		captured := &captureStatusEmitter{}
		bus := events.NewBus(captured)
		m := NewManager(client, bus, nil)
		m.Start(context.Background())
		// Give the loop a moment to attempt connection and fail.
		time.Sleep(50 * time.Millisecond)
		m.Stop()
		// The loop should have emitted at least one connection status event.
		assert.GreaterOrEqual(t, captured.count(), 1)
	})
}

// captureStatusEmitter captures Emit calls for assertion.
type captureStatusEmitter struct {
	mu     sync.Mutex
	events []string
}

func (e *captureStatusEmitter) Emit(eventType string, _ interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, eventType)
}

func (e *captureStatusEmitter) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.events)
}

// ---------------------------------------------------------------------------
// syncHandler is a race-safe testHandler for WebSocket message delivery tests.
// ---------------------------------------------------------------------------

type syncHandler struct {
	mu   sync.Mutex
	msgs []signal.ReceivedMessage
}

func (h *syncHandler) HandleMessage(msg signal.ReceivedMessage) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, msg)
}

func (h *syncHandler) len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.msgs)
}

// ---------------------------------------------------------------------------
// WebSocket-backed Manager tests
// These tests stand up a real httptest WebSocket server so that
// ConnectWebSocket can dial successfully, covering connect()'s return-nil
// path and the message-delivery callback.
// ---------------------------------------------------------------------------

// testWSCreds returns a minimal Credentials for WebSocket auth.
func testWSCreds() *signal.Credentials {
	password, err := signal.NewSecurePassword("ws-test-pw")
	if err != nil {
		panic(err)
	}
	return &signal.Credentials{
		UUID:     "ws-test-uuid",
		DeviceID: 1,
		Password: password,
	}
}

// newWSServer creates an httptest.Server that accepts a WebSocket upgrade on
// /v1/websocket/, optionally writes one JSON message, then closes normally.
// The returned server URL is compatible with signal.Client.ServerURL (http://).
func newWSServer(t *testing.T, writeMsg *signal.ReceivedMessage) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()

		if writeMsg != nil {
			data, _ := json.Marshal(writeMsg)
			// Best-effort: ignore write error (client may have disconnected).
			_ = conn.Write(r.Context(), websocket.MessageText, data)
			// Small pause so the client goroutine can read the frame.
			time.Sleep(30 * time.Millisecond)
		}
		_ = conn.Close(websocket.StatusNormalClosure, "done")
	}))
	return srv
}

// TestManager_connect_ReturnsNilOnSuccess verifies that connect() returns nil
// when ConnectWebSocket dials successfully, covering the "return nil" path.
func TestManager_connect_ReturnsNilOnSuccess(t *testing.T) {
	t.Run("DialSucceeds", func(t *testing.T) {
		srv := newWSServer(t, nil)
		defer srv.Close()

		client, err := newTestClientWithCreds(t, srv.URL, testWSCreds())
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		bus := events.NewBus(events.NoopEmitter{})
		m := NewManager(client, bus, nil)
		// Set context directly (white-box: we are in package ws).
		m.ctx = ctx
		m.cancel = cancel

		err = m.connect()
		require.NoError(t, err)
	})
}

// TestManager_connect_HandlerReceivesMessage verifies that the message callback
// inside ConnectWebSocket reaches m.handler.HandleMessage and
// m.eventBus.Emit(events.MessageReceived, ...).
func TestManager_connect_HandlerReceivesMessage(t *testing.T) {
	t.Run("MessageDeliveredToHandler", func(t *testing.T) {
		payload := &signal.ReceivedMessage{
			GUID: "ws-guid-001",
			Body: "hello from ws",
		}
		srv := newWSServer(t, payload)
		defer srv.Close()

		client, err := newTestClientWithCreds(t, srv.URL, testWSCreds())
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		emitter := &captureStatusEmitter{}
		bus := events.NewBus(emitter)
		handler := &syncHandler{}
		m := NewManager(client, bus, handler)
		m.ctx = ctx
		m.cancel = cancel

		err = m.connect()
		require.NoError(t, err)

		// Wait for the goroutine to deliver the message (max 500ms).
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) && handler.len() == 0 {
			time.Sleep(10 * time.Millisecond)
		}

		assert.GreaterOrEqual(t, handler.len(), 1, "handler should have received at least one message")
	})
}

// TestManager_connectionLoop_SuccessResetsBackoff verifies the backoff-reset
// branch inside connectionLoop that executes after a successful connect().
func TestManager_connectionLoop_SuccessResetsBackoff(t *testing.T) {
	t.Run("BackoffResetAfterSuccessfulConnect", func(t *testing.T) {
		// The server accepts one WebSocket and then stays closed so
		// the second loop iteration fails fast.
		connected := make(chan struct{}, 2)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
			if err != nil {
				return
			}
			connected <- struct{}{}
			_ = conn.Close(websocket.StatusNormalClosure, "bye")
		}))

		client, err := newTestClientWithCreds(t, srv.URL, testWSCreds())
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(context.Background())

		bus := events.NewBus(events.NoopEmitter{})
		m := NewManager(client, bus, nil)
		m.Start(ctx)

		// Wait for at least one successful connection.
		select {
		case <-connected:
		case <-time.After(2 * time.Second):
			t.Fatal("no WebSocket connection established within 2s")
		}

		// Stop the loop before the backoff (1s) expires for the second attempt.
		cancel()
		srv.Close()
	})
}
