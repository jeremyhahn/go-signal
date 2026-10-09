//go:build desktop

package ws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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

		// Waits for the event rather than sleeping and hoping. The previous
		// version slept 50ms and asserted a count, which depended on the dial
		// to an unreachable host failing inside that window — a wall-clock
		// assertion of exactly the kind testing-guidelines.md rules out.
		emitted := make(chan struct{}, 1)
		bus := events.NewBus(&signalOnStatusEmitter{ch: emitted})
		m := NewManager(client, bus, nil)
		m.Start(context.Background())
		t.Cleanup(m.Stop)

		select {
		case <-emitted:
		case <-time.After(10 * time.Second):
			t.Fatal("the connection loop emitted no connection-status event")
		}
	})
}

// signalOnStatusEmitter signals the first connection-status event, so a test
// can wait for it instead of sleeping.
type signalOnStatusEmitter struct{ ch chan struct{} }

func (e *signalOnStatusEmitter) Emit(eventType string, _ interface{}) {
	if eventType == string(events.ConnectionStatus) {
		select {
		case e.ch <- struct{}{}:
		default:
		}
	}
}

// captureStatusEmitter captures Emit calls for assertion.
type captureStatusEmitter struct {
	mu     sync.Mutex
	events []string
	// states records the connected value of each status event, so a test can
	// assert what a consumer was last TOLD rather than only how often.
	states []bool
}

func (e *captureStatusEmitter) Emit(eventType string, payload interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, eventType)
	if m, ok := payload.(map[string]bool); ok {
		if v, ok := m["connected"]; ok {
			e.states = append(e.states, v)
		}
	}
}

// last returns the connected value most recently delivered, or nil if nothing
// has been.
func (e *captureStatusEmitter) last() *bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.states) == 0 {
		return nil
	}
	v := e.states[len(e.states)-1]
	return &v
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
	password, err := signal.NewSecurePassword(context.Background(), "ws-test-pw")
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

		_, err = m.connect(ctx)
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

		_, err = m.connect(ctx)
		require.NoError(t, err)

		// Wait for the goroutine to deliver the message (max 500ms).
		deadline := time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) && handler.len() == 0 {
			time.Sleep(10 * time.Millisecond)
		}

		assert.GreaterOrEqual(t, handler.len(), 1, "handler should have received at least one message")
	})
}

// stepClock is the loop's view of time in a schedule test. Every reading
// advances it by step, so step decides how long each session appears to have
// lasted: zero for a server that drops the socket at once, stableSession for
// one that holds it open.
type stepClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(c.step)
	return c.t
}

// scheduleRecorder stands in for time.After so a test can READ the retry
// schedule instead of living through it — proving the delays escalate takes
// 15 s of real waiting otherwise, which testing-guidelines.md rules out.
type scheduleRecorder struct {
	mu     sync.Mutex
	delays []time.Duration
	want   int
	full   chan struct{}
}

func newScheduleRecorder(want int) *scheduleRecorder {
	return &scheduleRecorder{want: want, full: make(chan struct{})}
}

func (r *scheduleRecorder) After(d time.Duration) <-chan time.Time {
	r.mu.Lock()
	r.delays = append(r.delays, d)
	if len(r.delays) == r.want {
		close(r.full)
	}
	r.mu.Unlock()

	// The wait itself is instant; only its requested length is under test.
	ch := make(chan time.Time, 1)
	ch <- time.Time{}
	return ch
}

func (r *scheduleRecorder) recorded() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.delays...)
}

// startWithSchedule runs a manager against srv with the clock and the retry
// schedule under the test's control, and waits for want delays to be
// requested.
func startWithSchedule(t *testing.T, srv *countingWSServer, step time.Duration, want int) []time.Duration {
	t.Helper()

	client, err := newTestClientWithCreds(t, srv.URL, testWSCreds())
	require.NoError(t, err)

	sched := newScheduleRecorder(want)
	m := NewManager(client, events.NewBus(events.NoopEmitter{}), nil)
	// Before Start, so the loop goroutine does not race these writes.
	m.now = (&stepClock{step: step}).Now
	m.after = sched.After

	m.Start(context.Background())
	t.Cleanup(m.Stop)

	select {
	case <-sched.full:
	case <-time.After(30 * time.Second):
		t.Fatalf("only %d retries were scheduled, want %d", len(sched.recorded()), want)
	}
	m.Stop()

	return sched.recorded()[:want]
}

// TestManager_StartSupersedesThePreviousLoop is one half of the generation
// contract.
//
// Start used to overwrite m.cancel without cancelling the loop it replaced, so
// the first loop reconnected forever with nothing holding its cancel func —
// Stop could only reach the newest. Every restart leaked a goroutine and a
// socket. The assertion is that the superseded loop actually TERMINATES, which
// its done channel reports; a timeout means it was orphaned.
func TestManager_StartSupersedesThePreviousLoop(t *testing.T) {
	srv := newCountingWSServer(t)
	defer srv.Close()

	client, err := newTestClientWithCreds(t, srv.URL, testWSCreds())
	require.NoError(t, err)

	m := NewManager(client, events.NewBus(events.NoopEmitter{}), nil)
	m.Start(context.Background())
	first := m.currentGen()
	require.NotNil(t, first)

	m.Start(context.Background())
	t.Cleanup(m.Stop)

	require.NotSame(t, first, m.currentGen(), "the second Start did not take ownership")

	select {
	case <-first.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the superseded loop is still running: Start orphaned it")
	}
}

// The other half: a superseded loop must not report status. It has been
// cancelled but has not necessarily noticed, and its deferred final
// "disconnected" landing after the replacement has connected would report a
// live socket as down — and leave IsConnected lying about it.
func TestManager_SupersededLoopCannotPublish(t *testing.T) {
	srv := newCountingWSServer(t)
	defer srv.Close()

	client, err := newTestClientWithCreds(t, srv.URL, testWSCreds())
	require.NoError(t, err)

	captured := &captureStatusEmitter{}
	m := NewManager(client, events.NewBus(captured), nil)

	m.Start(context.Background())
	first := m.currentGen()
	require.NotNil(t, first)

	m.Start(context.Background())
	t.Cleanup(m.Stop)
	select {
	case <-first.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the superseded loop never exited")
	}

	// The replacement owns the manager. Drive the state the superseded loop
	// would have published on its way out.
	m.setConnected(m.currentGen(), true)
	m.setConnected(first, false)

	if !m.IsConnected() {
		t.Error("a superseded loop reported the live connection as disconnected")
	}
}

// takeOwnership installs a generation the way Start does, without launching a
// loop. This test is about the commit path, not the loop, and a live loop
// commits on its own schedule — it would trip the hook below before the
// interleaving under test could be set up.
//
// It mirrors Start's swap, including starting the replacement disconnected. If
// the two drift the helper stops standing for the thing it is named after.
func takeOwnership(m *Manager) *loopGeneration {
	gen := &loopGeneration{cancel: func() {}, done: make(chan struct{})}
	for {
		cur := m.status.Load()
		next := &status{gen: gen, published: cur != nil && cur.published}
		if m.status.CompareAndSwap(cur, next) {
			return gen
		}
	}
}

// TestManager_SupersededLoopCannotCommitAcrossTheHandoff is the regression
// test for the TOCTOU between authorization and commit.
//
// Checking ownership and publishing were two steps. A superseded loop could
// pass the check, be descheduled while a replacement took over AND connected,
// then commit its stale "disconnected" over a live socket — leaving
// IsConnected and every subscriber reporting a working connection as down.
// A sequential test cannot see this; the interleaving has to be forced, which
// is what beforeCommit is for.
func TestManager_SupersededLoopCannotCommitAcrossTheHandoff(t *testing.T) {
	client, err := newTestClient()
	require.NoError(t, err)

	captured := &captureStatusEmitter{}
	m := NewManager(client, events.NewBus(captured), nil)

	first := takeOwnership(m)

	var (
		armed  atomic.Bool
		paused = make(chan struct{})
		resume = make(chan struct{})
	)
	armed.Store(true)
	// CompareAndSwap, not sync.Once: Once BLOCKS later callers until the first
	// invocation RETURNS, so the replacement's commit would wait on the very
	// goroutine this test is deliberately holding — a deadlock, not a race.
	// Only the first caller pauses; every other one falls straight through.
	m.beforeCommit = func() {
		if armed.CompareAndSwap(true, false) {
			close(paused)
			<-resume
		}
	}

	stale := make(chan struct{})
	go func() {
		defer close(stale)
		m.setConnected(first, false)
	}()

	select {
	case <-paused:
	case <-time.After(30 * time.Second):
		t.Fatal("the stale commit never reached the commit point")
	}

	// The replacement takes ownership and connects while the old generation is
	// held mid-commit. The hook is disarmed, so these do not pause.
	second := takeOwnership(m)
	require.NotSame(t, first, second)
	m.setConnected(second, true)
	require.True(t, m.IsConnected(), "the replacement failed to publish")

	close(resume)
	select {
	case <-stale:
	case <-time.After(30 * time.Second):
		t.Fatal("the stale commit never returned")
	}

	if !m.IsConnected() {
		t.Error("the superseded loop committed its stale state over the live connection")
	}
	if last := captured.last(); last == nil || !*last {
		t.Error("the last event delivered says disconnected while the connection is live")
	}
}

// A subscriber is free to call Stop from its handler. Stop's NON-BLOCKING
// contract is the whole of what makes that safe here: it cancels and returns
// rather than waiting on the loop its own caller is running inside. Making
// Stop terminal against this delivery model hangs this test, which is the
// measurement behind the comment on Stop and the reason terminal Stop waits
// for #67's dispatcher rather than being bolted on.
//
// It also pins a hazard of synchronous delivery that is worth stating rather
// than discovering: Stop emits, so a handler that calls Stop is RE-ENTERED
// before its first invocation returns. The guard below is an atomic
// compare-and-swap and not a sync.Once for exactly that reason — Once blocks
// later callers until the first invocation RETURNS, so on one goroutine it
// deadlocks against itself. Written with a Once, this test hangs for 30s and
// blames the manager for a defect in its own double.
//
// Delivery moving to a dispatcher goroutine (#67) removes the re-entrancy
// along with the ordering problem; until then it is a documented property of
// this package, not an accident.
func TestManager_SubscriberCallingStopFromItsHandlerDoesNotDeadlock(t *testing.T) {
	client, err := newTestClient()
	require.NoError(t, err)

	bus := events.NewBus(events.NoopEmitter{})
	m := NewManager(client, bus, nil)
	gen := takeOwnership(m)

	var (
		armed     atomic.Bool
		reentered atomic.Bool
		inHandler atomic.Bool
	)
	armed.Store(true)
	bus.Subscribe(func(et events.EventType, _ interface{}) {
		if et != events.ConnectionStatus {
			return
		}
		if !inHandler.CompareAndSwap(false, true) {
			reentered.Store(true)
		}
		if armed.CompareAndSwap(true, false) {
			m.Stop()
		}
		inHandler.Store(false)
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.setConnected(gen, true)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("a subscriber calling Stop from its handler deadlocked the manager")
	}
	assert.False(t, m.IsConnected(), "Stop ran but the manager still reports connected")
	assert.True(t, reentered.Load(),
		"the handler was not re-entered: synchronous delivery is expected to re-enter it, "+
			"and a test that stopped observing that would stop guarding it")
}

// statusChanEmitter delivers each connection-status value on a channel, so a
// test can wait for a transition instead of polling for one. The buffer is
// generous because Emit runs on the manager's own goroutine: a full channel
// would block the loop rather than the test.
type statusChanEmitter struct{ ch chan bool }

func newStatusChanEmitter() *statusChanEmitter {
	return &statusChanEmitter{ch: make(chan bool, 32)}
}

func (e *statusChanEmitter) Emit(eventType string, payload interface{}) {
	if eventType != string(events.ConnectionStatus) {
		return
	}
	if m, ok := payload.(map[string]bool); ok {
		select {
		case e.ch <- m["connected"]:
		default:
		}
	}
}

// next returns the connection status delivered next, failing the test if none
// arrives. A missing event is the defect this is usually looking for, so it
// must fail rather than block.
func (e *statusChanEmitter) next(t *testing.T, what string) bool {
	t.Helper()
	select {
	case v := <-e.ch:
		return v
	case <-time.After(30 * time.Second):
		t.Fatalf("no status event was delivered for %s", what)
		return false
	}
}

// heldSecondDialServer completes the first WebSocket handshake and holds every
// later dial before accepting it, so a test can inspect the manager while a
// replacement generation's dial is still in flight. That window is where the
// handoff has to be honest: the old socket is already cancelled and the new
// one does not exist yet.
type heldSecondDialServer struct {
	*httptest.Server
	dials   atomic.Int32
	held    chan struct{}
	release chan struct{}
	once    sync.Once
}

func newHeldSecondDialServer(t *testing.T) *heldSecondDialServer {
	t.Helper()
	s := &heldSecondDialServer{
		held:    make(chan struct{}),
		release: make(chan struct{}),
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.dials.Add(1) > 1 {
			s.once.Do(func() { close(s.held) })
			<-s.release
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		<-r.Context().Done()
		_ = conn.CloseNow()
	}))
	// Released before Close so httptest is not left waiting on a held handler.
	t.Cleanup(func() {
		s.releaseHeld()
		s.Close()
	})
	return s
}

func (s *heldSecondDialServer) releaseHeld() {
	select {
	case <-s.release:
	default:
		close(s.release)
	}
}

// TestManager_RestartDoesNotInheritTheCancelledGenerationsConnectedState is the
// slow-dial restart case. Start cancels the generation it supersedes, so that
// generation's socket is going away — and a replacement that copied its
// connected flag reported a cancelled socket as live for as long as its own
// dial took, with no disconnected event in between to correct anyone.
//
// The server holds the replacement's dial open so the window is a state the
// test can stand in rather than a race it has to win. Without the fix the
// assertions fail two independent ways: IsConnected stays true, and the
// handoff emits nothing at all (the delivery side suppresses a repeat of
// "connected", which is exactly why the stale flag was invisible).
func TestManager_RestartDoesNotInheritTheCancelledGenerationsConnectedState(t *testing.T) {
	srv := newHeldSecondDialServer(t)

	client, err := newTestClientWithCreds(t, srv.URL, testWSCreds())
	require.NoError(t, err)

	status := newStatusChanEmitter()
	m := NewManager(client, events.NewBus(status), nil)
	t.Cleanup(m.Stop)

	m.Start(context.Background())
	// The first Start publishes the state it installs, which is disconnected:
	// a consumer is told where it stands before any dial resolves, rather than
	// hearing nothing until one succeeds.
	require.False(t, status.next(t, "the first Start"),
		"the first Start did not publish the disconnected state it installed")
	require.True(t, status.next(t, "the first generation connecting"),
		"the first generation never reported itself connected")
	require.True(t, m.IsConnected())

	// The replacement's dial is held by the server, so the handoff window
	// stays open for the assertions below.
	m.Start(context.Background())

	select {
	case <-srv.held:
	case <-time.After(30 * time.Second):
		t.Fatal("the replacement never dialled")
	}

	assert.False(t, m.IsConnected(),
		"the replacement inherited the cancelled generation's connected state")
	assert.False(t, status.next(t, "the handoff"),
		"no disconnected event was delivered when Start cancelled a live connection")

	srv.releaseHeld()
}

// Stop reports disconnected itself, before it returns. The loop's own final
// publish is ignored once it is no longer current, so without this a stopped
// manager would keep claiming to be connected until its goroutine happened to
// run — a window no caller can see or wait for.
func TestManager_StopReportsDisconnectedImmediately(t *testing.T) {
	srv := newCountingWSServer(t)
	defer srv.Close()

	client, err := newTestClientWithCreds(t, srv.URL, testWSCreds())
	require.NoError(t, err)

	m := NewManager(client, events.NewBus(events.NoopEmitter{}), nil)
	m.Start(context.Background())

	select {
	case <-srv.dials:
	case <-time.After(30 * time.Second):
		t.Fatal("the manager never connected")
	}

	m.Stop()
	if m.IsConnected() {
		t.Error("IsConnected still reports connected after Stop returned")
	}
}

// TestManager_ShortSessionsEscalateBackoff is the regression test for the
// reconnect storm.
//
// The backoff used to be reset on the handshake, before the session's lifetime
// was known. A server that accepts every socket and closes it immediately —
// exactly countingWSServer, and exactly what a rejecting or flapping server
// looks like in production — therefore reset the schedule on every attempt and
// was re-dialled once a second forever. maxBackoff was unreachable.
func TestManager_ShortSessionsEscalateBackoff(t *testing.T) {
	srv := newCountingWSServer(t)
	defer srv.Close()

	// step 0: every session lasts no time at all.
	got := startWithSchedule(t, srv, 0, 4)

	want := []time.Duration{baseBackoff, 2 * baseBackoff, 4 * baseBackoff, 8 * baseBackoff}
	require.Equal(t, want, got,
		"a server that accepts and closes at once must be retried more slowly each time")
}

// The escalation must not punish a connection that actually worked: a socket
// that lived and then dropped is retried promptly, or a single overnight
// network blip would leave the client waiting 30 s to come back.
func TestManager_StableSessionResetsBackoff(t *testing.T) {
	srv := newCountingWSServer(t)
	defer srv.Close()

	// Each session appears to outlive stableSession, so each one earns a
	// fresh schedule and the delay never grows.
	got := startWithSchedule(t, srv, stableSession, 4)

	want := []time.Duration{baseBackoff, baseBackoff, baseBackoff, baseBackoff}
	require.Equal(t, want, got, "a session that proved healthy must reset the schedule")
}

// drop looks like to the client, which is the condition under test.
type countingWSServer struct {
	*httptest.Server
	dials chan struct{}
}

func newCountingWSServer(t *testing.T) *countingWSServer {
	t.Helper()
	s := &countingWSServer{dials: make(chan struct{}, 16)}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		select {
		case s.dials <- struct{}{}:
		default:
		}
		// Drop it straight away: the client must notice and come back.
		_ = conn.Close(websocket.StatusNormalClosure, "bye")
	}))
	return s
}

// TestManager_ReconnectsAfterServerClose is the regression test for #37.
//
// ConnectWebSocketSession returns at handshake, not on close, so before it
// existed the manager had no way to learn a socket had dropped: it stayed
// connected=true forever and never re-dialled, silently ending real-time
// delivery after the first disconnect.
//
// The assertion is on receiving a SECOND accept from the server, not on
// elapsed time — testing-guidelines.md rules out sleeps, and a sleep would
// make this flaky in exactly the way #36 was.
func TestManager_ReconnectsAfterServerClose(t *testing.T) {
	srv := newCountingWSServer(t)
	defer srv.Close()

	client, err := newTestClientWithCreds(t, srv.URL, testWSCreds())
	require.NoError(t, err)

	m := NewManager(client, events.NewBus(events.NoopEmitter{}), nil)
	m.Start(context.Background())
	t.Cleanup(m.Stop)

	// First connection.
	select {
	case <-srv.dials:
	case <-time.After(10 * time.Second):
		t.Fatal("the manager never made its first connection")
	}

	// The server closed it. Without the session-done signal the loop would sit
	// on ctx.Done() forever and this would time out.
	select {
	case <-srv.dials:
	case <-time.After(10 * time.Second):
		t.Fatal("the manager did not reconnect after the server closed the socket")
	}
}

// A dropped connection must also be published as disconnected. Reporting
// connected=true over a dead socket is what makes a UI claim delivery is
// working when it has silently stopped.
func TestManager_DroppedConnectionIsPublishedAsDisconnected(t *testing.T) {
	srv := newCountingWSServer(t)
	defer srv.Close()

	client, err := newTestClientWithCreds(t, srv.URL, testWSCreds())
	require.NoError(t, err)

	captured := &captureStatusEmitter{}
	m := NewManager(client, events.NewBus(captured), nil)
	m.Start(context.Background())
	t.Cleanup(m.Stop)

	select {
	case <-srv.dials:
	case <-time.After(10 * time.Second):
		t.Fatal("no connection was made")
	}
	// Wait for the reconnect, which can only happen after the drop was seen.
	select {
	case <-srv.dials:
	case <-time.After(10 * time.Second):
		t.Fatal("no reconnect, so the drop was never detected")
	}

	m.Stop()
	if got := captured.count(); got < 2 {
		t.Errorf("status events = %d, want at least a connect and a disconnect", got)
	}
}
