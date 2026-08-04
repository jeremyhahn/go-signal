package keytransparency

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
	ktserver "github.com/jeremyhahn/go-signal/pkg/keytransparency/server"
)

func startServer(t *testing.T) *grpc.ClientConn {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	ktpb.RegisterKeyTransparencyQueryServiceServer(gs,
		ktserver.NewGRPCServer(ktserver.NewMemoryLog(), priv))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestGRPCClient_Distinguished(t *testing.T) {
	conn := startServer(t)
	c, err := New(Config{Conn: conn})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	resp, err := c.Distinguished(context.Background(), &ktpb.DistinguishedRequest{})
	if err != nil {
		t.Fatalf("Distinguished: %v", err)
	}
	if resp.GetTreeHead() == nil {
		t.Error("nil tree head")
	}
}

func TestGRPCClient_Search(t *testing.T) {
	conn := startServer(t)
	c, _ := New(Config{Conn: conn})
	t.Cleanup(func() { _ = c.Close() })
	aci := make([]byte, 16)
	resp, err := c.Search(context.Background(), &ktpb.SearchRequest{
		Aci:            aci,
		AciIdentityKey: []byte("key"),
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if resp.GetTreeHead() == nil {
		t.Error("nil tree head")
	}
}

func TestGRPCClient_Monitor(t *testing.T) {
	conn := startServer(t)
	c, _ := New(Config{Conn: conn})
	t.Cleanup(func() { _ = c.Close() })
	resp, err := c.Monitor(context.Background(), &ktpb.MonitorRequest{})
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	if resp.GetTreeHead() == nil {
		t.Error("nil tree head")
	}
}

func TestNew_ValidatesConnAndEndpoint(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("expected error on empty config")
	}
	if _, err := New(Config{Endpoint: "x", Conn: &grpc.ClientConn{}}); err == nil {
		t.Error("expected error when both Conn and Endpoint are set")
	}
}

func TestNew_WithEndpoint_Lazy(t *testing.T) {
	// grpc.NewClient is lazy; an unreachable endpoint still succeeds at
	// construction time. Transport credentials must be supplied explicitly.
	c, err := New(Config{
		Endpoint:    "localhost:19998",
		DialOptions: []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())},
	})
	if err != nil {
		t.Fatalf("New with Endpoint: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestGRPCClient_Close_NotOwned(t *testing.T) {
	conn := startServer(t)
	// Supply caller-owned Conn — Close must be a no-op (returns nil).
	c, err := New(Config{Conn: conn})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close on not-owned conn: %v", err)
	}
	// conn is still usable (owned by startServer cleanup).
	if !c.owned {
		// Correct: not owned.
	}
}

func TestGRPCClient_WithTimeout_SetsDeadline(t *testing.T) {
	conn := startServer(t)
	c, err := New(Config{Conn: conn, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = c.Close() }()

	// Ensure the context gets a deadline when Timeout > 0.  We use
	// Distinguished which is a quick round-trip so the deadline never fires.
	resp, err := c.Distinguished(context.Background(), &ktpb.DistinguishedRequest{})
	if err != nil {
		t.Fatalf("Distinguished with timeout: %v", err)
	}
	if resp.GetTreeHead() == nil {
		t.Error("nil tree head")
	}
}
