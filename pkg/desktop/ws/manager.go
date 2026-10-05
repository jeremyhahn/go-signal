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

// Manager maintains dual WebSocket connections to the Signal server:
//   - Authenticated: persistent connection for message delivery
//   - Unauthenticated: rotated connection for public operations
//
// It handles automatic reconnection with exponential backoff and
// dispatches incoming messages through the event bus.
type Manager struct {
	client   *signal.Client
	eventBus *events.Bus
	handler  MessageHandler

	// status is the owning loop and the connection state as ONE value, so the
	// two can only change together. Splitting them was the defect: a
	// superseded loop could pass an ownership check, be descheduled while a
	// replacement started and connected, then commit its stale
	// "disconnected" over a live socket. Every writer compare-and-swaps, so a
	// generation that lost ownership between reading and committing loses the
	// swap and drops its update instead of landing it.
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

	// stableSession is how long a session must last to count as healthy and
	// so earn a fresh schedule. It is maxBackoff deliberately: a session that
	// outlives the longest retry delay is one the escalation was never meant
	// to be pacing. A shorter threshold would let a server that accepts and
	// immediately closes reset the schedule on every attempt, which is the
	// fixed-rate reconnect storm this exists to prevent.
	stableSession = maxBackoff
)

// loopGeneration is one Start's connection loop. A manager has at most one
// live at a time; an older one that has been cancelled but is still winding
// down must not act as though it were current.
type loopGeneration struct {
	cancel context.CancelFunc
	// done closes when the loop returns. Nothing in production waits on it —
	// Stop stays non-blocking, which is what keeps #36's deadlock closed — but
	// it lets a test prove a superseded loop actually terminated rather than
	// being orphaned.
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

// Start begins the WebSocket connection loop. It runs until Stop is called, or
// until a later Start supersedes it.
//
// A second Start cancels the first. Without that, the earlier loop kept
// reconnecting forever with nothing holding its cancel func — Stop could only
// reach the newest — so every restart leaked a goroutine and a socket.
//
// The loop's context is passed to it rather than stored on the struct: a
// field read inside the goroutine is unsynchronised against this write.
func (m *Manager) Start(ctx context.Context) {
	loopCtx, cancel := context.WithCancel(ctx)
	gen := &loopGeneration{cancel: cancel, done: make(chan struct{})}

	// Publish first, then cancel: the moment the swap lands the old loop is no
	// longer current, so anything it publishes on the way out is ignored even
	// though it may not have noticed the cancellation yet.
	//
	// A replacement starts DISCONNECTED, whatever the generation it supersedes
	// was reporting. Start cancels that generation's context two lines below,
	// so its socket is going away; carrying its connected flag across the
	// handoff tells every consumer that a cancelled socket is live until the
	// replacement's own dial resolves. A slow dial makes that window as long
	// as the dial takes, and a failing one as long as the backoff — and no
	// disconnected event is emitted in it, so nothing corrects the belief.
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
			// Publishing here is what makes the handoff observable: a restart
			// of a live manager emits the disconnect it just caused, and a
			// first Start tells a consumer where it stands before any dial
			// resolves.
			m.emit(false, changed)
			break
		}
	}

	go m.connectionLoop(loopCtx, gen)
}

// Stop shuts the WebSocket connections down by cancelling the loop's context.
// It does NOT wait for the loop to exit.
//
// Making Stop terminal is desirable — it is what would let a caller read
// settled state afterwards — but it cannot be done while status events are
// emitted synchronously from the loop goroutine: a subscriber that calls Stop
// from its handler would block the very loop Stop waits for. Measured, not
// theorised.
//
// That is a consequence of where delivery runs, so it is fixed by moving
// delivery rather than by anything Stop can do. Owner decision 14 / E1 puts
// delivery on a dispatcher goroutine and states that subscribers may call Stop
// from a callback, which removes the deadlock; terminal Stop lands with that
// change, tracked as #67. Until then Stop keeps its original non-blocking
// behaviour.
//
// Safe before Start and more than once.
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
	// The loop's own final publish is ignored now that it is not current, so
	// stopping is what reports disconnected — and it does so before Stop
	// returns rather than whenever the goroutine next runs, which is the only
	// version a caller can rely on.
	//
	// This emits, so a synchronous subscriber runs here. It does NOT reopen
	// #36: Stop never waits on the loop, so a subscriber calling Stop from its
	// handler finds current already nil and returns immediately.
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

			// Only a session that LASTED resets the schedule. Resetting on the
			// handshake alone made the escalation unreachable: a server that
			// accepts every socket and closes it immediately would be dialled
			// every second forever, because each accept reset the backoff
			// before the session's lifetime was known.
			if m.now().Sub(opened) >= stableSession {
				backoff = baseBackoff
			}
		} else {
			// A failed dial must publish too. Without this the very first
			// status a consumer receives is nothing at all: a client that can
			// never reach the server is never told it is disconnected,
			// because setConnected only publishes on the first call or a
			// change and neither happens if it is never called.
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

// setConnected publishes a connection state on behalf of one loop generation,
// and does nothing if that generation is no longer the manager's.
//
// The guard is what stops a superseded loop from reporting a live socket as
// down: a cancelled loop has not necessarily noticed yet, and its deferred
// final publish can land after its replacement has already connected.
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

// emit publishes a connection state on the bus for the first publish and
// thereafter only when the value actually changes. A failing server is retried
// on a backoff, and re-emitting "disconnected" on every attempt floods
// consumers with an event that carries no new information.
//
// Delivery is SYNCHRONOUS AND UNORDERED, and that is a deliberate interim
// state rather than an oversight. Two writers reaching the bus concurrently
// can deliver out of order, so a subscriber can be left holding a value
// IsConnected contradicts.
//
// Ordering it correctly is a decided design that does not belong in this
// change: owner decision 14 / E1 (2026-08-23) rules a bounded queue drained by
// one dispatcher goroutine outside the loop goroutine, drop-oldest overflow
// with a counter, and subscribers free to call Stop from a callback. Tracked
// as #67, which carries the ordering and lost-notification tests. Sequence
// numbers and hand-off batons were both tried here and are both the option the
// ruling declined; nothing is left behind pretending to order what it cannot.
func (m *Manager) emit(v, changed bool) {
	if !changed {
		return
	}
	m.eventBus.Emit(events.ConnectionStatus, map[string]bool{"connected": v})
}

// connect establishes a single WebSocket session and returns a channel closed
// when that session ends. It returns as soon as the handshake completes, not
// when the connection drops — the returned channel is what reports the latter.
//
// The caller sets connected only after this returns without error. Setting it
// first meant the flag read true for the whole of every failed connection
// attempt, so "connected" reported that we were about to try rather than that
// we had succeeded.
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
