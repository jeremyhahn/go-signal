package websocket

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	cachememory "github.com/jeremyhahn/go-signal/pkg/cache/memory"
	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// fakeFlusher returns a configurable list of envelopes and records each call.
type fakeFlusher struct {
	mu    sync.Mutex
	calls int
	envs  []*messages.Envelope
	err   error
}

func (f *fakeFlusher) flush(_ context.Context, _ string, _ uint64) ([]*messages.Envelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.envs, f.err
}

func (f *fakeFlusher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestNewSessionManagerWithCache_NotNil(t *testing.T) {
	c := cachememory.New()
	defer func() { _ = c.Close() }()
	flusher := func(context.Context, string, uint64) ([]*messages.Envelope, error) { return nil, nil }

	m := NewSessionManagerWithCache(managerTestLogger(), c, flusher)
	if m == nil {
		t.Fatal("NewSessionManagerWithCache returned nil")
		return
	}
	if m.cache == nil {
		t.Error("expected cache to be wired")
	}
	if m.flusher == nil {
		t.Error("expected flusher to be wired")
	}
}

func TestNewSessionManagerWithCache_NilCacheStillSetsFlusher(t *testing.T) {
	flusher := func(context.Context, string, uint64) ([]*messages.Envelope, error) { return nil, nil }

	m := NewSessionManagerWithCache(managerTestLogger(), nil, flusher)
	if m.cache != nil {
		t.Error("expected cache to be nil")
	}
	if m.flusher == nil {
		t.Error("expected flusher to be wired even when cache is nil")
	}
}

func TestNotifyChannel_Format(t *testing.T) {
	got := notifyChannel("uuid-abc", 7)
	want := "signal:ws:notify:uuid-abc:7"
	if got != want {
		t.Errorf("notifyChannel = %q, want %q", got, want)
	}
}

// TestNotifyMessageAvailable_LocalFlush exercises the cache==nil path: the
// notify call should flush the local session via the registered flusher.
func TestNotifyMessageAvailable_LocalFlush(t *testing.T) {
	flusher := &fakeFlusher{
		envs: []*messages.Envelope{
			{ID: 1, Type: messages.EnvelopeTypeCiphertext, DestinationUUID: "uuid-1"},
			{ID: 2, Type: messages.EnvelopeTypeCiphertext, DestinationUUID: "uuid-1"},
		},
	}
	m := NewSessionManagerWithCache(managerTestLogger(), nil, flusher.flush)

	s := newTestSession("uuid-1", 1)
	m.Register(s)

	if err := m.NotifyMessageAvailable(context.Background(), "uuid-1", 1); err != nil {
		t.Fatalf("NotifyMessageAvailable returned error: %v", err)
	}

	if got := flusher.callCount(); got != 1 {
		t.Errorf("flusher call count = %d, want 1", got)
	}

	// Both envelopes should be enqueued on the session's send channel.
	for i := 0; i < 2; i++ {
		select {
		case data := <-s.send:
			if len(data) == 0 {
				t.Errorf("envelope %d: enqueued message is empty", i)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("envelope %d: nothing on send channel", i)
		}
	}
}

// TestNotifyMessageAvailable_LocalFlush_NoSession verifies that a notify for
// an unregistered destination is a harmless no-op.
func TestNotifyMessageAvailable_LocalFlush_NoSession(t *testing.T) {
	flusher := &fakeFlusher{}
	m := NewSessionManagerWithCache(managerTestLogger(), nil, flusher.flush)

	if err := m.NotifyMessageAvailable(context.Background(), "missing", 99); err != nil {
		t.Fatalf("NotifyMessageAvailable returned error: %v", err)
	}
	if got := flusher.callCount(); got != 0 {
		t.Errorf("flusher should not be called when no local session: got %d", got)
	}
}

// TestNotifyMessageAvailable_CrossInstance simulates two instances sharing a
// cache: instance A publishes a notify; instance B holds the session and is
// expected to flush in response.
func TestNotifyMessageAvailable_CrossInstance(t *testing.T) {
	c := cachememory.New()
	defer func() { _ = c.Close() }()

	flusherB := &fakeFlusher{
		envs: []*messages.Envelope{{ID: 7, Type: messages.EnvelopeTypeCiphertext, DestinationUUID: "uuid-x"}},
	}
	instanceA := NewSessionManagerWithCache(managerTestLogger(), c, func(context.Context, string, uint64) ([]*messages.Envelope, error) {
		t.Helper()
		t.Errorf("instance A flusher should not be invoked")
		return nil, nil
	})
	instanceB := NewSessionManagerWithCache(managerTestLogger(), c, flusherB.flush)

	// Session is held by instance B only.
	session := newTestSession("uuid-x", 3)
	instanceB.Register(session)
	defer instanceB.Unregister(session)

	// Give the subscription goroutine a moment to start.
	time.Sleep(20 * time.Millisecond)

	// Instance A publishes the wake-up notify.
	if err := instanceA.NotifyMessageAvailable(context.Background(), "uuid-x", 3); err != nil {
		t.Fatalf("publish from instance A failed: %v", err)
	}

	// Wait for the message to be enqueued on instance B's session.
	select {
	case data := <-session.send:
		if len(data) == 0 {
			t.Error("envelope enqueued but body empty")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("instance B did not flush in response to notify within deadline")
	}

	if got := flusherB.callCount(); got != 1 {
		t.Errorf("instance B flusher call count = %d, want 1", got)
	}
}

// TestSubscription_TerminatesOnSessionClose verifies that the per-session
// pub/sub goroutine exits when the session is closed (no leaked goroutine).
func TestSubscription_TerminatesOnSessionClose(t *testing.T) {
	c := cachememory.New()
	defer func() { _ = c.Close() }()

	flusher := &fakeFlusher{}
	m := NewSessionManagerWithCache(managerTestLogger(), c, flusher.flush)

	s := newTestSession("uuid-end", 1)
	m.Register(s)
	time.Sleep(20 * time.Millisecond) // let subscription start

	// Closing the session should terminate the subscription goroutine.
	close(s.done)

	// Publish after close: the flusher must NOT be invoked.
	if _, err := c.Publish(context.Background(), notifyChannel("uuid-end", 1), nil); err != nil {
		t.Fatalf("publish failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if got := flusher.callCount(); got != 0 {
		t.Errorf("flusher should not be called after session close: got %d", got)
	}
}

// TestNotifyMessageAvailable_FlusherErrorPropagates exercises the local path
// to confirm that flusher errors are surfaced to the caller. The remote path
// logs+swallows by design (delivery is best-effort across the bus).
func TestNotifyMessageAvailable_FlusherErrorPropagates(t *testing.T) {
	wantErr := errors.New("store down")
	flusher := &fakeFlusher{err: wantErr}
	m := NewSessionManagerWithCache(managerTestLogger(), nil, flusher.flush)

	s := newTestSession("uuid-err", 1)
	m.Register(s)

	err := m.NotifyMessageAvailable(context.Background(), "uuid-err", 1)
	if !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped flusher error, got %v", err)
	}
}

// TestSessionManager_NewSessionManager_NoCacheNoFlusher exercises the
// pre-existing local-only constructor: NotifyMessageAvailable must be a
// harmless no-op since the caller is expected to have used DeliverMessage.
func TestSessionManager_NewSessionManager_NoCacheNoFlusher(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s := newTestSession("uuid-bare", 1)
	m.Register(s)

	if err := m.NotifyMessageAvailable(context.Background(), "uuid-bare", 1); err != nil {
		t.Fatalf("NotifyMessageAvailable returned error in bare mode: %v", err)
	}
	// No payloads should be enqueued.
	select {
	case <-s.send:
		t.Error("unexpected enqueue in bare mode")
	default:
	}
}
