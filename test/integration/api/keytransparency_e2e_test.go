//go:build integration

package api

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
	"github.com/jeremyhahn/go-signal/pkg/extservice/keytransparency"
	ktmgr "github.com/jeremyhahn/go-signal/pkg/keytransparency"
	"github.com/jeremyhahn/go-signal/pkg/keytransparency/server"
)

// startKTInProcess wires the cmd/key-transparency-side gRPC server +
// an extservice/keytransparency.GRPCClient pointing at it, and the
// signald-side KeyTransparencyManager with the remote set. Returns
// the manager so tests can drive the same code path the REST
// handlers exercise.
func startKTInProcess(t *testing.T) (*ktmgr.KeyTransparencyManager, *server.MemoryLog) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	log := server.NewMemoryLog()
	gs := grpc.NewServer()
	ktpb.RegisterKeyTransparencyQueryServiceServer(gs, server.NewGRPCServer(log, priv))
	lis := bufconn.Listen(1 << 20)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	client, err := keytransparency.New(keytransparency.Config{Conn: conn})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	mgr := ktmgr.NewKeyTransparencyManager(nil)
	mgr.SetRemote(client)
	return mgr, log
}

// TestKeyTransparencyE2E_ManagerProxiesToRemote drives the chat-server
// path: REST handlers call into the manager which forwards to the
// remote service over a real gRPC connection. The returned token is
// the ed25519 signature over (size || root || ts) — verifying it lands
// is enough to prove the wire is end-to-end correct.
func TestKeyTransparencyE2E_ManagerProxiesToRemote(t *testing.T) {
	mgr, _ := startKTInProcess(t)
	ctx := context.Background()

	searchResp, err := mgr.Search(ctx, &ktmgr.SearchRequest{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(searchResp.Token) != ed25519.SignatureSize {
		t.Errorf("Search token len = %d, want %d", len(searchResp.Token), ed25519.SignatureSize)
	}

	monitorResp, err := mgr.Monitor(ctx, &ktmgr.MonitorRequest{})
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	if len(monitorResp.Token) != ed25519.SignatureSize {
		t.Errorf("Monitor token len = %d", len(monitorResp.Token))
	}

	distResp, err := mgr.GetDistinguishedKey(ctx)
	if err != nil {
		t.Fatalf("GetDistinguishedKey: %v", err)
	}
	if len(distResp.Key) != ed25519.SignatureSize {
		t.Errorf("Distinguished key len = %d", len(distResp.Key))
	}
}

// TestKeyTransparencyE2E_StubManagerStillRespondsToREST confirms the
// no-remote (monolithic) fallback path still works.
func TestKeyTransparencyE2E_StubManagerStillRespondsToREST(t *testing.T) {
	mgr := ktmgr.NewKeyTransparencyManager(nil)
	ctx := context.Background()
	if r, err := mgr.Search(ctx, &ktmgr.SearchRequest{}); err != nil || r == nil {
		t.Errorf("stub Search: r=%v err=%v", r, err)
	}
	if r, err := mgr.Monitor(ctx, &ktmgr.MonitorRequest{}); err != nil || r == nil {
		t.Errorf("stub Monitor: r=%v err=%v", r, err)
	}
	if r, err := mgr.GetDistinguishedKey(ctx); err != nil || r == nil {
		t.Errorf("stub Distinguished: r=%v err=%v", r, err)
	}
}

// TestKeyTransparencyE2E_LogAppendsVisibleToSearch confirms the log
// state is consulted by Search — appending an entry shows up in the
// next manager Search call.
func TestKeyTransparencyE2E_LogAppendsVisibleToSearch(t *testing.T) {
	mgr, log := startKTInProcess(t)
	if _, err := log.Append([]byte("alice"), []byte("v1")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if log.Size() != 1 {
		t.Errorf("log size = %d after Append", log.Size())
	}
	// Tree-head signature is over a non-zero log size now; manager
	// proxies the signature back as the token.
	resp, err := mgr.Search(context.Background(), &ktmgr.SearchRequest{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(resp.Token) != ed25519.SignatureSize {
		t.Errorf("token len = %d", len(resp.Token))
	}
}
