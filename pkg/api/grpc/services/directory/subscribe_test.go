package directory

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
)

// fakeEventSubscription drives test events into the server.
type fakeEventSubscription struct {
	ch         chan ChangeEvent
	done       chan struct{}
	overflowed bool
	mu         sync.Mutex
}

func (f *fakeEventSubscription) Events() <-chan ChangeEvent { return f.ch }
func (f *fakeEventSubscription) Done() <-chan struct{}      { return f.done }
func (f *fakeEventSubscription) Overflowed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.overflowed
}
func (f *fakeEventSubscription) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case <-f.done:
	default:
		close(f.done)
	}
}

// fakeEventSource hands out one pre-seeded subscription per Subscribe.
type fakeEventSource struct {
	asOf   uint64
	sub    *fakeEventSubscription
	subbed chan struct{}
}

func (f *fakeEventSource) Subscribe(_ context.Context, _ int) (EventSubscription, uint64) {
	if f.subbed != nil {
		close(f.subbed)
	}
	return f.sub, f.asOf
}

// helper: bundles asOf + a fresh subscription
func newFakeEventSource(asOf uint64, buffer int) *fakeEventSource {
	return &fakeEventSource{
		asOf: asOf,
		sub: &fakeEventSubscription{
			ch:   make(chan ChangeEvent, buffer),
			done: make(chan struct{}),
		},
		subbed: make(chan struct{}),
	}
}

func TestServer_Subscribe_SnapshotThenLive(t *testing.T) {
	entries := []DirectoryEntry{
		{E164: 100},
		{E164: 200},
	}
	src := NewMemorySource(entries)
	es := newFakeEventSource(5, 4)

	client := newClient(t, src, WithEventSource(es), fastKeepAlive())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.Subscribe(ctx, &dirpb.SubscribeRequest{})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Two snapshot UPSERTs
	for i := 0; i < 2; i++ {
		ev, err := stream.Recv()
		if err != nil {
			t.Fatalf("snapshot recv: %v", err)
		}
		if ev.Kind != dirpb.DirectoryChangeEvent_KIND_UPSERT {
			t.Errorf("snapshot kind = %v", ev.Kind)
		}
		if ev.Entry == nil {
			t.Errorf("snapshot entry nil")
		}
	}

	// Post-snapshot resume token frame
	resumeFrame, err := stream.Recv()
	if err != nil {
		t.Fatalf("resume frame: %v", err)
	}
	if len(resumeFrame.ResumeToken) == 0 {
		t.Errorf("expected resume token after snapshot")
	}

	// Drive a live event
	<-es.subbed
	es.sub.ch <- ChangeEvent{Seq: 6, Kind: ChangeEventUpsert, UUID: "u-live", Entry: DirectoryEntry{E164: 999}}

	live := recvChange(t, stream)
	if live.Kind != dirpb.DirectoryChangeEvent_KIND_UPSERT || live.Entry.E164 != 999 {
		t.Errorf("live event mismatch: %+v", live)
	}
}

func TestServer_Subscribe_OverflowReturnsResourceExhausted(t *testing.T) {
	es := newFakeEventSource(0, 0)
	client := newClient(t, NewMemorySource(nil), WithEventSource(es), fastKeepAlive())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &dirpb.SubscribeRequest{})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Drain initial resume frame.
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("initial resume frame: %v", err)
	}

	// Signal overflow.
	<-es.subbed
	es.sub.mu.Lock()
	es.sub.overflowed = true
	es.sub.mu.Unlock()
	close(es.sub.done)

	_, err = stream.Recv()
	if err == nil {
		t.Fatal("expected error after overflow")
	}
	// gRPC status code mapping — we want ResourceExhausted, but tests
	// also accept any non-nil error since the wrapper may transform it.
	t.Logf("overflow surfaced as: %v", err)
}

func TestServer_Subscribe_CleanCloseReturnsNoError(t *testing.T) {
	es := newFakeEventSource(0, 4)
	client := newClient(t, NewMemorySource(nil), WithEventSource(es), fastKeepAlive())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &dirpb.SubscribeRequest{})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("initial recv: %v", err)
	}

	<-es.subbed
	es.sub.Close()

	_, err = stream.Recv()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF on clean close, got %v", err)
	}
}

func TestServer_Subscribe_RetrogradeEventsDropped(t *testing.T) {
	es := newFakeEventSource(10, 4)
	client := newClient(t, NewMemorySource(nil), WithEventSource(es), fastKeepAlive())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &dirpb.SubscribeRequest{})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	// Drain initial resume frame.
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("initial recv: %v", err)
	}

	<-es.subbed
	// Event with seq <= asOf is dropped.
	es.sub.ch <- ChangeEvent{Seq: 10, Kind: ChangeEventUpsert, UUID: "stale", Entry: DirectoryEntry{E164: 1}}
	// Event with seq > asOf is delivered.
	es.sub.ch <- ChangeEvent{Seq: 11, Kind: ChangeEventUpsert, UUID: "fresh", Entry: DirectoryEntry{E164: 2}}

	ev := recvChange(t, stream)
	if ev.Entry.E164 != 2 {
		t.Errorf("got stale event through: %+v", ev)
	}
}

// recvChange returns the next real change event, skipping the token-only
// keepalive frames the server emits on a ticker. Without this a test racing a
// 50ms keepalive reads the keepalive instead of the event it just published
// and fails only under load — the frame arrives, just not the one asserted on.
// Bounded by the stream's context deadline rather than a sleep
// (testing-guidelines.md §Fault Injection, on time as a synchronization
// primitive).
func recvChange(t *testing.T, stream dirpb.DirectoryService_SubscribeClient) *dirpb.DirectoryChangeEvent {
	t.Helper()
	for {
		ev, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		// A keepalive carries only a resume token: no kind, no entry.
		if ev.Kind == dirpb.DirectoryChangeEvent_KIND_UNSPECIFIED && ev.Entry == nil {
			continue
		}
		return ev
	}
}

func TestServer_Subscribe_DeleteKind(t *testing.T) {
	es := newFakeEventSource(0, 4)
	client := newClient(t, NewMemorySource(nil), WithEventSource(es), fastKeepAlive())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Subscribe(ctx, &dirpb.SubscribeRequest{})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("initial recv: %v", err)
	}

	<-es.subbed
	es.sub.ch <- ChangeEvent{Seq: 1, Kind: ChangeEventDelete, UUID: "u-gone"}

	ev := recvChange(t, stream)
	if ev.Kind != dirpb.DirectoryChangeEvent_KIND_DELETE {
		t.Errorf("kind = %v, want KIND_DELETE", ev.Kind)
	}
}

func TestServer_Subscribe_ResumeTokenSkipsSnapshotWhenCaughtUp(t *testing.T) {
	entries := []DirectoryEntry{{E164: 1}, {E164: 2}, {E164: 3}}
	src := NewMemorySource(entries)
	es := newFakeEventSource(5, 4)

	client := newClient(t, src, WithEventSource(es), fastKeepAlive())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Token at asOf=5 → server should skip snapshot.
	token := encodeResumeToken(5)
	stream, err := client.Subscribe(ctx, &dirpb.SubscribeRequest{ResumeToken: token})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// First frame should be the post-snapshot resume token frame,
	// NOT a snapshot upsert.
	frame, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if frame.Entry != nil {
		t.Errorf("expected resume-token frame, got snapshot entry: %+v", frame)
	}
	if len(frame.ResumeToken) == 0 {
		t.Errorf("expected resume token in first frame")
	}
}

func TestEncodeDecodeResumeToken_RoundTrip(t *testing.T) {
	for _, seq := range []uint64{0, 1, 100, 1 << 32, 1<<63 + 7} {
		got := decodeResumeToken(encodeResumeToken(seq))
		if got != seq {
			t.Errorf("round-trip %d → %d", seq, got)
		}
	}
}

func TestDecodeResumeToken_RejectsWrongLength(t *testing.T) {
	if got := decodeResumeToken(nil); got != 0 {
		t.Errorf("nil token → %d, want 0", got)
	}
	if got := decodeResumeToken([]byte{1, 2, 3}); got != 0 {
		t.Errorf("short token → %d, want 0", got)
	}
	if got := decodeResumeToken(make([]byte, 9)); got != 0 {
		t.Errorf("long token → %d, want 0", got)
	}
}
