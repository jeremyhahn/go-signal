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

	// subscribes counts handler entries, so a test can wait for a RECONNECT
	// rather than infer one. Without it, a test that cancels the context
	// cannot tell the production abort path from its own cancel.
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
	// Registered HERE, not at each call site, so no test can forget it. That
	// is not hypothetical: waitFor's t.Fatalf skips whatever close() the test
	// was going to do at the end, the handler stays parked on <-released, and
	// a deferred gs.Stop() then waits on a handler that can never return — so
	// the very regression the timeout exists to REPORT hangs the process
	// instead. Registering it in one test and not its siblings is how that
	// shipped.
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

// waitFor blocks until pred returns true, and FAILS the test if it never does.
//
// Every wait in this file used to fall THROUGH on timeout into the assertions,
// so a wait that never succeeded produced whatever confusing message the
// assertion happened to have — "token not persisted: []" for a token that
// simply had not been written yet. Failing here instead names the condition
// that was actually waited on.
//
// The predicate must be the state the assertions READ. Waiting on one thing
// and asserting another is what made these flaky: the wait observed the
// directory reflecting frame N-1 while the claim was about the token store
// written at frame N, with nothing ordering them (#72).
//
// A poll is the right instrument here, not a timing bet: SubscribeAndApply
// signals nothing when it has applied an event, and a signal from the fake
// service would only prove frames were SENT, not applied — a hook at the start
// of the work rather than at its end. What makes this not a sleep is that the
// predicate is the asserted state and a timeout is a failure, not a shrug.
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

	// Wait for BOTH the entry frames and the resume-token frame. The token is
	// the LAST frame the fake sends, so waiting only for the directory breaks
	// one frame early and the token assertion below then races it (#72).
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
	// Server's first frame is a token-only frame (Entry=nil, Kind=UNSPECIFIED).
	// Previously this never tripped the `cleared` flag and subsequent
	// real events were also gated out. The fix Replaces unconditionally
	// at subscribe start, so a token-only first frame is fine and the
	// following Upsert flows through.
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
	// The retries alone do not prove the production abort fired: the loop
	// could read for ever and this test would still finish, because IT
	// cancels the context below. The abort tears the stream down and
	// reconnects, so a SECOND Subscribe is the observable that separates the
	// two.
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
		// A sentinel AFTER the delete, so the test has something to wait for
		// that proves the stream got past it. Without this there is nothing
		// observable: "500 is absent" is true before the upsert as well as
		// after the delete, which is what made the original wait vacuous, and
		// "500 is present" is a state the very next frame destroys, so waiting
		// for THAT times out instead. The completion marker has to sit where
		// the claim ends.
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

	// Wait for the sentinel that follows the delete, which is the only state
	// here that proves the stream advanced past it.
	//
	// Waiting for "Count() == 0" was vacuous: a fresh directory is ALREADY
	// empty, so the loop broke on its first iteration before any frame was
	// applied and the assertion below was trivially true. Measured on the
	// original: with applyEvent replaced by a no-op — nothing applied at all,
	// UUID index never populated — this test passed 5/5 in 0.004s while its
	// siblings failed. It could not detect the absence of the feature it is
	// named for.
	//
	// Waiting for "500 is present" without gating the stream does not work
	// either, and that is worth recording: the delete is the very next frame,
	// so the upsert is a state the stream races past. Measured at 20/20
	// timeouts. The gate above is what makes it observable.
	waitFor(t, "the sentinel following the ACI-resolved delete", func() bool {
		_, ok := dir.Lookup(999)
		return ok
	})

	if _, ok := dir.Lookup(500); ok {
		t.Errorf("E164=500 should be deleted via ACI lookup")
	}
	// Only the sentinel remains: 500 was added and then removed. Without this
	// the test cannot tell a resolved delete from an upsert that never landed.
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
