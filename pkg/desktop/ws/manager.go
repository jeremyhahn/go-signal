//go:build desktop

// Package ws manages persistent WebSocket connections to the Signal server
// for real-time message delivery, typing indicators, and read receipts.
package ws

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/desktop/events"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// Manager maintains dual WebSocket connections to the Signal server:
//   - Authenticated: persistent connection for message delivery
//   - Unauthenticated: rotated connection for public operations
//
// It handles automatic reconnection with exponential backoff and
// dispatches incoming messages through the event bus.
type Manager struct {
	client    *signal.Client
	eventBus  *events.Bus
	ctx       context.Context
	cancel    context.CancelFunc
	connected atomic.Bool
	mu        sync.Mutex
	handler   MessageHandler
}

// MessageHandler processes decoded WebSocket messages.
type MessageHandler interface {
	HandleMessage(msg signal.ReceivedMessage)
}

// NewManager creates a WebSocket manager.
func NewManager(client *signal.Client, eventBus *events.Bus, handler MessageHandler) *Manager {
	return &Manager{
		client:   client,
		eventBus: eventBus,
		handler:  handler,
	}
}

// Start begins the WebSocket connection loop. It runs until Stop is called.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.mu.Unlock()

	go m.connectionLoop()
}

// Stop gracefully shuts down the WebSocket connections.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
}

// IsConnected reports whether the authenticated WebSocket is connected.
func (m *Manager) IsConnected() bool {
	return m.connected.Load()
}

// connectionLoop manages the authenticated WebSocket with reconnection.
func (m *Manager) connectionLoop() {
	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		err := m.connect()
		if err != nil {
			m.connected.Store(false)
			m.eventBus.Emit(events.ConnectionStatus, map[string]bool{"connected": false})

			select {
			case <-m.ctx.Done():
				return
			case <-time.After(backoff):
				backoff = min(backoff*2, maxBackoff)
			}
			continue
		}

		// Connection succeeded -- reset backoff.
		backoff = time.Second
	}
}

// connect establishes a single WebSocket session and reads messages
// until the connection drops or context is cancelled.
func (m *Manager) connect() error {
	m.connected.Store(true)
	m.eventBus.Emit(events.ConnectionStatus, map[string]bool{"connected": true})

	// Use the SDK's ConnectWebSocket which establishes the connection
	// and reads messages in a loop.
	err := m.client.ConnectWebSocket(m.ctx, func(msg signal.ReceivedMessage) {
		if m.handler != nil {
			m.handler.HandleMessage(msg)
		}
		m.eventBus.Emit(events.MessageReceived, msg)
	})
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "websocket connect", err)
	}

	return nil
}
