package directory

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
)

// fastKeepAlive accelerates the Subscribe keep-alive ticker so
// tests that wait for the next resume-token frame don't burn 30s.
// Append it to opts via newClient.
func fastKeepAlive() ServerOption {
	return WithSubscribeKeepAlive(50 * time.Millisecond)
}

func newClient(t *testing.T, source AccountSource, opts ...ServerOption) dirpb.DirectoryServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	dirpb.RegisterDirectoryServiceServer(gs, NewServer(source, opts...))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return dirpb.NewDirectoryServiceClient(conn)
}

func TestNewServer_PanicsWithoutSource(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	NewServer(nil)
}

func TestServer_ListEntries_StreamsAll(t *testing.T) {
	var aci, pni [16]byte
	aci[0] = 1
	pni[1] = 2
	entries := []DirectoryEntry{
		{E164: 100, ACI: aci, PNI: pni},
		{E164: 200, PNI: pni},
	}
	client := newClient(t, NewMemorySource(entries))
	stream, err := client.ListEntries(context.Background(), &dirpb.ListEntriesRequest{})
	if err != nil {
		t.Fatalf("ListEntries: %v", err)
	}
	count := 0
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		count++
		_ = msg
	}
	if count != 2 {
		t.Errorf("got %d entries, want 2", count)
	}
}

func TestServer_Subscribe_UnimplementedWithoutEventSource(t *testing.T) {
	client := newClient(t, NewMemorySource(nil))
	stream, err := client.Subscribe(context.Background(), &dirpb.SubscribeRequest{})
	if err != nil {
		t.Fatalf("Subscribe initial: %v", err)
	}
	_, err = stream.Recv()
	if err == nil {
		t.Error("expected error when no EventSource wired")
	}
}

// sourceErr lets tests inject an error from ListAll.
type sourceErr struct{}

func (sourceErr) ListAll(_ context.Context, _ func(DirectoryEntry) error) error {
	return errors.New("source boom")
}

func TestServer_ListEntries_SurfacesSourceError(t *testing.T) {
	client := newClient(t, sourceErr{})
	stream, _ := client.ListEntries(context.Background(), &dirpb.ListEntriesRequest{})
	_, err := stream.Recv()
	if err == nil {
		t.Error("expected source error to surface")
	}
}

func TestWithSubscribeBuffer_PositiveValue_Overrides(t *testing.T) {
	src := NewMemorySource(nil)
	s := NewServer(src, WithSubscribeBuffer(512))
	if s.subBufferSize != 512 {
		t.Errorf("subBufferSize = %d, want 512", s.subBufferSize)
	}
}

func TestWithSubscribeBuffer_NonPositiveValue_KeepsDefault(t *testing.T) {
	src := NewMemorySource(nil)
	s := NewServer(src, WithSubscribeBuffer(0))
	if s.subBufferSize != defaultSubscribeBuffer {
		t.Errorf("subBufferSize = %d, want %d", s.subBufferSize, defaultSubscribeBuffer)
	}
	s2 := NewServer(src, WithSubscribeBuffer(-1))
	if s2.subBufferSize != defaultSubscribeBuffer {
		t.Errorf("subBufferSize = %d, want %d", s2.subBufferSize, defaultSubscribeBuffer)
	}
}

func TestMemorySource_ListAll_ContextCancelled_Aborts(t *testing.T) {
	entries := make([]DirectoryEntry, 3)
	for i := range entries {
		entries[i].E164 = uint64(i + 1)
	}
	src := NewMemorySource(entries)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before listing

	seen := 0
	err := src.ListAll(ctx, func(e DirectoryEntry) error {
		seen++
		return nil
	})
	// ctx is already cancelled so the first ctx.Err() check must abort immediately.
	if err == nil {
		t.Error("expected context cancellation error from ListAll")
	}
	if seen > 0 {
		t.Errorf("expected 0 entries seen after cancellation, got %d", seen)
	}
}

func TestServer_ListAll_ErrorFromFn_Propagates(t *testing.T) {
	entries := []DirectoryEntry{{E164: 1}}
	src := NewMemorySource(entries)

	ctx := context.Background()
	want := errors.New("fn error")
	got := src.ListAll(ctx, func(e DirectoryEntry) error {
		return want
	})
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}
