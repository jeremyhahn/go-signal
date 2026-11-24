package cdsi

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
)

// fakeDirectoryService drives crafted Subscribe streams from a test.
type fakeDirectoryService struct {
	dirpb.UnimplementedDirectoryServiceServer

	mu       sync.Mutex
	frames   []*dirpb.DirectoryChangeEvent
	released chan struct{}
	gotToken chan []byte

	// releaseOnce makes release idempotent. The handler parks on <-released,
	// so a test that fails before its close() leaks that goroutine for the
	// life of the process — and waitFor's t.Fatalf is exactly such an early
	// exit. Tests now register release via t.Cleanup AND may call it inline.
	releaseOnce sync.Once

	// subscribes counts handler entries, so a test can wait for a reconnect.
	subscribes atomic.Int64

	// gateAfter, when > 0, parks the handler after sending that many frames
	// until gate is closed. It exists so a test can observe an intermediate
	// state that the next frame destroys — an upsert immediately followed by
	// the delete that removes it.
	gateAfter int
	gate      chan struct{}
}

// release unparks the handler. Safe to call more than once and from a
// t.Cleanup registered before the test can fail.
func (f *fakeDirectoryService) release() {
	f.releaseOnce.Do(func() { close(f.released) })
}

func newFakeDirectoryService(t *testing.T, frames []*dirpb.DirectoryChangeEvent) *fakeDirectoryService {
	t.Helper()
	f := &fakeDirectoryService{
		frames:   frames,
		released: make(chan struct{}),
		gotToken: make(chan []byte, 1),
	}
	// Registered here so a failed wait cannot leave a handler parked and hang gs.Stop().
	t.Cleanup(f.release)
	return f
}

func (f *fakeDirectoryService) Subscribe(req *dirpb.SubscribeRequest, stream dirpb.DirectoryService_SubscribeServer) error {
	f.subscribes.Add(1)
	select {
	case f.gotToken <- req.GetResumeToken():
	default:
	}
	f.mu.Lock()
	frames := f.frames
	gateAfter, gate := f.gateAfter, f.gate
	f.mu.Unlock()
	for i, frame := range frames {
		if err := stream.Send(frame); err != nil {
			return err
		}
		if gate != nil && i+1 == gateAfter {
			select {
			case <-gate:
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
		}
	}
	// Both, deliberately. release() is the normal path; the stream context is
	// the one that holds when a test dies before reaching it. Waiting only on
	// released makes the fake's liveness depend on every test remembering
	// something, which is the assumption that failed above.
	select {
	case <-f.released:
	case <-stream.Context().Done():
	}
	return nil
}

func newClient(t *testing.T, svc dirpb.DirectoryServiceServer) (dirpb.DirectoryServiceClient, *grpc.Server) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	dirpb.RegisterDirectoryServiceServer(gs, svc)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return dirpb.NewDirectoryServiceClient(conn), gs
}

// waitFor polls pred, the state the assertions read, and fails the test on timeout.
func waitFor(t *testing.T, what string, pred func() bool) {
	t.Helper()
	const (
		limit = 5 * time.Second
		tick  = 2 * time.Millisecond
	)
	timeout := time.After(limit)
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		if pred() {
			return
		}
		select {
		case <-timeout:
			if pred() {
				return
			}
			t.Fatalf("timed out after %v waiting for %s", limit, what)
		case <-ticker.C:
		}
	}
}

func TestSubscribeAndApply_RequiresClient(t *testing.T) {
	err := SubscribeAndApply(context.Background(), SubscribeConfig{Directory: NewMemoryDirectory()})
	if err == nil {
		t.Error("expected error on missing client")
	}
}

func TestSubscribeAndApply_RequiresDirectory(t *testing.T) {
	client, gs := newClient(t, newFakeDirectoryService(t, nil))
	defer gs.Stop()
	err := SubscribeAndApply(context.Background(), SubscribeConfig{Client: client})
	if err == nil {
		t.Error("expected error on missing directory")
	}
}

func TestSubscribeAndApply_AppliesSnapshotAndLiveEvents(t *testing.T) {
	var aci1 [16]byte
	aci1[0] = 1
	frames := []*dirpb.DirectoryChangeEvent{
		// Snapshot
		{Kind: dirpb.DirectoryChangeEvent_KIND_UPSERT, Entry: &dirpb.DirectoryEntry{E164: 100, Aci: aci1[:]}},
		// Live upsert
		{Kind: dirpb.DirectoryChangeEvent_KIND_UPSERT, Entry: &dirpb.DirectoryEntry{E164: 200}},
		// Live delete (by E164)
		{Kind: dirpb.DirectoryChangeEvent_KIND_DELETE, Entry: &dirpb.DirectoryEntry{E164: 100}},
		// Resume token
		{ResumeToken: []byte{0, 0, 0, 0, 0, 0, 0, 7}},
	}
	svc := newFakeDirectoryService(t, frames)
	client, gs := newClient(t, svc)
	defer gs.Stop()

	dir := NewMemoryDirectory()
	tokens := NewMemoryResumeTokenStore()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- SubscribeAndApply(ctx, SubscribeConfig{
			Client: client, Directory: dir, TokenStore: tokens,
			MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond,
		})
	}()

	// Wait for the entry frames and the resume token, the last frame the fake sends.
	waitFor(t, "the entry frames to be applied", func() bool {
		if dir.Count() != 1 {
			return false
		}
		_, ok := dir.Lookup(200)
		return ok
	})
	waitFor(t, "the resume token to be persisted", func() bool {
		tok, _ := tokens.Load(ctx)
		return len(tok) == 8 && tok[7] == 7
	})
	if dir.Count() != 1 {
		t.Fatalf("got %d entries, want 1", dir.Count())
	}
	if _, ok := dir.Lookup(200); !ok {
		t.Errorf("E164=200 missing")
	}
	if _, ok := dir.Lookup(100); ok {
		t.Errorf("E164=100 should be deleted")
	}

	// Resume token persisted.
	tok, _ := tokens.Load(ctx)
	if len(tok) != 8 || tok[7] != 7 {
		t.Errorf("token not persisted: %v", tok)
	}

	cancel()
	svc.release()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("loop returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("loop did not exit on ctx cancel")
	}
}

func TestSubscribeAndApply_TokenOnlyFirstFrame_DoesNotDeadlock(t *testing.T) {
	// The first frame is token-only; the directory is replaced at subscribe start, so the following Upsert applies.
	frames := []*dirpb.DirectoryChangeEvent{
		{ResumeToken: []byte{0, 0, 0, 0, 0, 0, 0, 1}},
		{Kind: dirpb.DirectoryChangeEvent_KIND_UPSERT,
			Entry: &dirpb.DirectoryEntry{E164: 300}},
	}
	svc := newFakeDirectoryService(t, frames)
	client, gs := newClient(t, svc)
	defer gs.Stop()

	dir := NewMemoryDirectory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = SubscribeAndApply(ctx, SubscribeConfig{
			Client:    client,
			Directory: dir,
		})
	}()

	waitFor(t, "the upsert after a token-only first frame", func() bool {
		_, ok := dir.Lookup(300)
		return ok
	})
	if _, ok := dir.Lookup(300); !ok {
		t.Errorf("upsert after token-only first frame never applied")
	}
	svc.release()
}

func TestSubscribeAndApply_TokenSavePersistentFailures_AbortStream(t *testing.T) {
	// Drive a stream that emits resume tokens; the token store
	// rejects every Save. After maxTokenSaveFailures, the subscribe
	// loop must abort the stream so the next reconnect can use a
	// fresh token store or trigger operator alerts.
	frames := make([]*dirpb.DirectoryChangeEvent, 10)
	for i := range frames {
		frames[i] = &dirpb.DirectoryChangeEvent{
			ResumeToken: []byte{0, 0, 0, 0, 0, 0, 0, byte(i + 1)},
		}
	}
	svc := newFakeDirectoryService(t, frames)
	client, gs := newClient(t, svc)
	defer gs.Stop()

	dir := NewMemoryDirectory()
	failing := &failingTokenStore{err: errors.New("disk full")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- SubscribeAndApply(ctx, SubscribeConfig{
			Client:     client,
			Directory:  dir,
			TokenStore: failing,
			MinBackoff: 10 * time.Millisecond,
			MaxBackoff: 50 * time.Millisecond,
		})
	}()

	// Wait for the retries the assertion below counts, rather than sleeping a
	// guessed 200ms and hoping five happened. The old form was a timing bet in
	// both directions: it could cancel before the fifth retry on a loaded
	// machine, and it could not tell a working retry loop from a fast one.
	waitFor(t, "the token store to be retried at least 5 times", func() bool {
		return failing.Calls() >= 5
	})
	// A second Subscribe proves the abort reconnected, as distinct from the test's own cancel.
	waitFor(t, "the aborted stream to reconnect", func() bool {
		return svc.subscribes.Load() >= 2
	})
	cancel()
	svc.release()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not exit after cancel")
	}
	if failing.Calls() < 5 {
		t.Errorf("token store was not retried (calls=%d)", failing.Calls())
	}
}

// failingTokenStore always returns err from Save while tracking the
// number of attempts.
type failingTokenStore struct {
	err   error
	mu    sync.Mutex
	calls int
}

func (s *failingTokenStore) Load(_ context.Context) ([]byte, error) { return nil, nil }
func (s *failingTokenStore) Save(_ context.Context, _ []byte) error {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.err
}
func (s *failingTokenStore) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestSubscribeAndApply_DeleteByACIUsesUUIDIndex(t *testing.T) {
	var aci [16]byte
	aci[0] = 9
	frames := []*dirpb.DirectoryChangeEvent{
		// Upsert with ACI fills the index.
		{Kind: dirpb.DirectoryChangeEvent_KIND_UPSERT, Entry: &dirpb.DirectoryEntry{E164: 500, Aci: aci[:]}},
		// Delete with no E164 but same ACI → resolved via index.
		{Kind: dirpb.DirectoryChangeEvent_KIND_DELETE, Entry: &dirpb.DirectoryEntry{Aci: aci[:]}},
		// A sentinel after the delete gives the test a state that proves the stream passed it.
		{Kind: dirpb.DirectoryChangeEvent_KIND_UPSERT, Entry: &dirpb.DirectoryEntry{E164: 999}},
	}
	svc := newFakeDirectoryService(t, frames)
	// Hold the stream after the upsert so the test can see 500 present before
	// the delete removes it. Without this the upsert is a state the next frame
	// destroys, and the test cannot distinguish "added then deleted via the
	// ACI index" from "never added at all" — which is the whole claim.
	svc.gateAfter = 1
	svc.gate = make(chan struct{})
	client, gs := newClient(t, svc)
	defer gs.Stop()

	dir := NewMemoryDirectory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = SubscribeAndApply(ctx, SubscribeConfig{Client: client, Directory: dir}) }()

	waitFor(t, "the ACI-carrying upsert to be applied", func() bool {
		_, ok := dir.Lookup(500)
		return ok
	})
	close(svc.gate)

	// Wait for the sentinel that follows the delete.
	waitFor(t, "the sentinel following the ACI-resolved delete", func() bool {
		_, ok := dir.Lookup(999)
		return ok
	})

	if _, ok := dir.Lookup(500); ok {
		t.Errorf("E164=500 should be deleted via ACI lookup")
	}
	// Only the sentinel remains: 500 was added and then removed.
	if got := dir.Count(); got != 1 {
		t.Errorf("directory holds %d entries, want only the sentinel", got)
	}
}

func TestSubscribeAndApply_PassesResumeTokenOnReconnect(t *testing.T) {
	// First connection delivers events + token, then closes (we
	// trigger close via context done on the released channel).
	svc := newFakeDirectoryService(t, []*dirpb.DirectoryChangeEvent{
		{ResumeToken: []byte{0, 0, 0, 0, 0, 0, 0, 42}},
	})
	client, gs := newClient(t, svc)
	defer gs.Stop()

	tokens := NewMemoryResumeTokenStore()
	dir := NewMemoryDirectory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = SubscribeAndApply(ctx, SubscribeConfig{
			Client: client, Directory: dir, TokenStore: tokens,
			MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond,
		})
	}()

	// Confirm first connection received empty token.
	select {
	case got := <-svc.gotToken:
		if len(got) != 0 {
			t.Errorf("initial token = %v, want empty", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first Subscribe never invoked")
	}

	waitFor(t, "the resume token to be persisted before reconnect", func() bool {
		tok, _ := tokens.Load(ctx)
		return len(tok) == 8 && tok[7] == 42
	})

	// Close the first stream → loop reconnects.
	svc.release()

	// Confirm reconnect uses the persisted token.
	select {
	case got := <-svc.gotToken:
		if len(got) != 8 || got[7] != 42 {
			t.Errorf("reconnect token = %v, want [...,42]", got)
		}
	case <-time.After(2 * time.Second):
		t.Error("reconnect did not happen")
	}
}

func TestMemoryResumeTokenStore_RoundTrip(t *testing.T) {
	s := NewMemoryResumeTokenStore()
	if tok, err := s.Load(context.Background()); err != nil || len(tok) != 0 {
		t.Errorf("initial Load = %v %v", tok, err)
	}
	if err := s.Save(context.Background(), []byte{1, 2, 3}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	tok, _ := s.Load(context.Background())
	if string(tok) != "\x01\x02\x03" {
		t.Errorf("round-trip = %v", tok)
	}
}

func TestPadTo8(t *testing.T) {
	got := padTo8([]byte{0xFF})
	if len(got) != 8 || got[7] != 0xFF {
		t.Errorf("short pad = %v", got)
	}
	got = padTo8(make([]byte, 8))
	if len(got) != 8 {
		t.Errorf("equal-length pad: %v", got)
	}
	got = padTo8(make([]byte, 10))
	if len(got) != 8 {
		t.Errorf("long truncate: %v", got)
	}
}

// fakeDirEOFService closes the stream immediately — for verifying
// EOF retry path.
type fakeDirEOFService struct {
	dirpb.UnimplementedDirectoryServiceServer
	hits int32
	mu   sync.Mutex
}

func (f *fakeDirEOFService) Subscribe(_ *dirpb.SubscribeRequest, _ dirpb.DirectoryService_SubscribeServer) error {
	f.mu.Lock()
	f.hits++
	hits := f.hits
	f.mu.Unlock()
	if hits > 3 {
		// Don't busy-loop — block long enough for tests to cancel.
		<-time.After(5 * time.Second)
	}
	return io.EOF
}

func TestSubscribeAndApply_RetriesOnEOF(t *testing.T) {
	svc := &fakeDirEOFService{}
	client, gs := newClient(t, svc)
	defer gs.Stop()

	dir := NewMemoryDirectory()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- SubscribeAndApply(ctx, SubscribeConfig{
			Client: client, Directory: dir,
			MinBackoff: 5 * time.Millisecond, MaxBackoff: 10 * time.Millisecond,
		})
	}()
	<-done

	svc.mu.Lock()
	hits := svc.hits
	svc.mu.Unlock()
	if hits < 2 {
		t.Errorf("expected at least 2 retries, got %d", hits)
	}
}
