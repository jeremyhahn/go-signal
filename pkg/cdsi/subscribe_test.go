package cdsi

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
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
}

func newFakeDirectoryService(frames []*dirpb.DirectoryChangeEvent) *fakeDirectoryService {
	return &fakeDirectoryService{
		frames:   frames,
		released: make(chan struct{}),
		gotToken: make(chan []byte, 1),
	}
}

func (f *fakeDirectoryService) Subscribe(req *dirpb.SubscribeRequest, stream dirpb.DirectoryService_SubscribeServer) error {
	select {
	case f.gotToken <- req.GetResumeToken():
	default:
	}
	f.mu.Lock()
	frames := f.frames
	f.mu.Unlock()
	for _, frame := range frames {
		if err := stream.Send(frame); err != nil {
			return err
		}
	}
	<-f.released
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

func TestSubscribeAndApply_RequiresClient(t *testing.T) {
	err := SubscribeAndApply(context.Background(), SubscribeConfig{Directory: NewMemoryDirectory()})
	if err == nil {
		t.Error("expected error on missing client")
	}
}

func TestSubscribeAndApply_RequiresDirectory(t *testing.T) {
	client, gs := newClient(t, newFakeDirectoryService(nil))
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
	svc := newFakeDirectoryService(frames)
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

	// Wait for events to be applied.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if dir.Count() == 1 {
			if _, ok := dir.Lookup(200); ok {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
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
	close(svc.released)
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
	svc := newFakeDirectoryService(frames)
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

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := dir.Lookup(300); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := dir.Lookup(300); !ok {
		t.Errorf("upsert after token-only first frame never applied")
	}
	close(svc.released)
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
	svc := newFakeDirectoryService(frames)
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

	// The subscribe loop should keep retrying; we cancel after a
	// short wait to terminate the goroutine.
	time.Sleep(200 * time.Millisecond)
	cancel()
	close(svc.released)
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
	}
	svc := newFakeDirectoryService(frames)
	client, gs := newClient(t, svc)
	defer gs.Stop()

	dir := NewMemoryDirectory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = SubscribeAndApply(ctx, SubscribeConfig{Client: client, Directory: dir}) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if dir.Count() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := dir.Lookup(500); ok {
		t.Errorf("E164=500 should be deleted via ACI lookup")
	}
	close(svc.released)
}

func TestSubscribeAndApply_PassesResumeTokenOnReconnect(t *testing.T) {
	// First connection delivers events + token, then closes (we
	// trigger close via context done on the released channel).
	svc := newFakeDirectoryService([]*dirpb.DirectoryChangeEvent{
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

	// Wait for token to be persisted.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tok, _ := tokens.Load(ctx); len(tok) == 8 && tok[7] == 42 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Close the first stream → loop reconnects.
	close(svc.released)

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
