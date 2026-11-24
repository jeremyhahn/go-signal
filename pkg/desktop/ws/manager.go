//go:build desktop

// Package ws manages persistent WebSocket connections to the Signal server
// for real-time message delivery, typing indicators, and read receipts.
package ws

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/desktop/events"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// Manager keeps an authenticated and an unauthenticated WebSocket to the server, reconnecting with backoff and dispatching messages on the event bus.
type Manager struct {
	client   *signal.Client
	eventBus *events.Bus
	handler  MessageHandler

	// status holds the owning loop and connection state as one value; every writer compare-and-swaps, so a superseded loop cannot commit.
	status atomic.Pointer[status]

	// beforeCommit runs between reading the status and committing the
	// replacement. Production leaves it nil; it exists so a test can hold a
	// loop at exactly the instant this race needs.
	beforeCommit func()

	// now and after are the loop's only view of time, so a test can observe
	// the retry schedule without waiting for it. NewManager wires them to the
	// real clock; nothing else sets them.
	now   func() time.Time
	after func(time.Duration) <-chan time.Time
}

// status is the manager's ownership and connection state at an instant. It is
// immutable once published; changing it means swapping in a replacement.
type status struct {
	// gen owns the manager, or nil once Stop has run. Only this generation
	// may change the connection state.
	gen *loopGeneration
	// connected is what IsConnected reports.
	connected bool
	// published records whether any state has reached the bus, so the first
	// one is delivered even though it matches the zero value. Without it a
	// consumer starting up would never be told it is disconnected.
	published bool
}

// Reconnection schedule.
const (
	// baseBackoff is the delay after a connection that had proved healthy.
	baseBackoff = time.Second

	// maxBackoff caps the delay between reconnection attempts.
	maxBackoff = 30 * time.Second

	// stableSession is how long a session must last to reset the backoff; maxBackoff, so accept-and-close servers do not cause a reconnect storm.
	stableSession = maxBackoff
)

// loopGeneration is one Start's connection loop. A manager has at most one
// live at a time; an older one that has been cancelled but is still winding
// down must not act as though it were current.
type loopGeneration struct {
	cancel context.CancelFunc
	// done closes when the loop returns, so tests can prove a superseded loop ended; Stop never waits on it.
	done chan struct{}
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
		now:      time.Now,
		after:    time.After,
	}
}

// Start runs the connection loop until Stop or a later Start, which cancels this one; the loop gets its context as an argument.
func (m *Manager) Start(ctx context.Context) {
	loopCtx, cancel := context.WithCancel(ctx)
	gen := &loopGeneration{cancel: cancel, done: make(chan struct{})}

	// Publish the new generation, then cancel the old; the replacement starts disconnected.
	for {
		cur := m.status.Load()
		next := &status{gen: gen}
		changed := true
		if cur != nil {
			changed = !cur.published || cur.connected
		}
		next.published = true
		if m.status.CompareAndSwap(cur, next) {
			if cur != nil && cur.gen != nil {
				cur.gen.cancel()
			}
			// Publish the handoff so consumers learn the state before any dial resolves.
			m.emit(false, changed)
			break
		}
	}

	go m.connectionLoop(loopCtx, gen)
}

// Stop cancels the loop's context without waiting for it, so a subscriber may call it from a handler. Safe before Start and more than once.
func (m *Manager) Stop() {
	var (
		gen     *loopGeneration
		changed bool
	)
	for {
		cur := m.status.Load()
		if cur == nil || cur.gen == nil {
			return
		}
		next := &status{connected: false, published: true}
		if m.status.CompareAndSwap(cur, next) {
			gen, changed = cur.gen, !cur.published || cur.connected
			break
		}
	}
	gen.cancel()
	// Stop reports disconnected itself before returning; the loop's own final publish is ignored.
	m.emit(false, changed)
}

// currentGen returns the generation that owns the manager, or nil. Tests use
// it to name a generation; production reads the whole status instead.
func (m *Manager) currentGen() *loopGeneration {
	if st := m.status.Load(); st != nil {
		return st.gen
	}
	return nil
}

// IsConnected reports whether the authenticated WebSocket is connected.
func (m *Manager) IsConnected() bool {
	st := m.status.Load()
	return st != nil && st.connected
}

// connectionLoop manages the authenticated WebSocket with reconnection.
func (m *Manager) connectionLoop(ctx context.Context, gen *loopGeneration) {
	defer close(gen.done)
	// A manager that is not looping is not connected. Publishing that on the
	// way out is what lets Stop's caller read a settled value.
	defer m.setConnected(gen, false)

	backoff := baseBackoff

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sessionDone, err := m.connect(ctx)
		if err == nil {
			m.setConnected(gen, true)
			opened := m.now()

			select {
			case <-ctx.Done():
				return
			case <-sessionDone:
				// Server close, network drop, or read error. The socket is
				// gone and nothing else will tell us.
			}
			m.setConnected(gen, false)

			// Only a session that lasted resets the backoff.
			if m.now().Sub(opened) >= stableSession {
				backoff = baseBackoff
			}
		} else {
			// A failed dial publishes too, so consumers learn they are disconnected.
			m.setConnected(gen, false)
		}

		// Reached after a failed dial OR a dropped session. Both are paced by
		// the same backoff: a server that accepts and immediately closes would
		// otherwise be reconnected to in a hot loop.
		select {
		case <-ctx.Done():
			return
		case <-m.after(backoff):
			backoff = min(backoff*2, maxBackoff)
		}
	}
}

// setConnected publishes a state for one loop generation, and nothing once that generation is superseded.
func (m *Manager) setConnected(gen *loopGeneration, v bool) {
	for {
		cur := m.status.Load()
		if cur == nil || cur.gen != gen {
			// Superseded or stopped: not ours to report.
			return
		}
		if m.beforeCommit != nil {
			m.beforeCommit()
		}
		next := &status{gen: gen, connected: v, published: true}
		if m.status.CompareAndSwap(cur, next) {
			m.emit(v, !cur.published || cur.connected != v)
			return
		}
		// Lost the swap: ownership or state moved under us. Re-read and
		// re-check rather than committing against a status that is gone.
	}
}

// emit publishes the first state and then only changes; delivery is synchronous and unordered across concurrent writers.
func (m *Manager) emit(v, changed bool) {
	if !changed {
		return
	}
	m.eventBus.Emit(events.ConnectionStatus, map[string]bool{"connected": v})
}

// connect opens one WebSocket session and returns at handshake with a channel closed when it ends; the caller sets connected only on success.
func (m *Manager) connect(ctx context.Context) (<-chan struct{}, error) {
	sessionDone, err := m.client.ConnectWebSocketSession(ctx, func(msg signal.ReceivedMessage) {
		if m.handler != nil {
			m.handler.HandleMessage(msg)
		}
		m.eventBus.Emit(events.MessageReceived, msg)
	})
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "websocket connect", err)
	}
	return sessionDone, nil
}
