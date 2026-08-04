package server

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
)

func newClient(t *testing.T, log Log, priv ed25519.PrivateKey) ktpb.KeyTransparencyQueryServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	ktpb.RegisterKeyTransparencyQueryServiceServer(gs, NewGRPCServer(log, priv))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return ktpb.NewKeyTransparencyQueryServiceClient(conn)
}

func TestNewGRPCServer_PanicsWithoutLog(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	_, priv, _ := ed25519.GenerateKey(nil)
	NewGRPCServer(nil, priv)
}

func TestNewGRPCServer_PanicsWithoutSigner(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	NewGRPCServer(NewMemoryLog(), nil)
}

func TestGRPCServer_Distinguished_ReturnsSignedHead(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	log := NewMemoryLog()
	c := newClient(t, log, priv)
	resp, err := c.Distinguished(context.Background(), &ktpb.DistinguishedRequest{})
	if err != nil {
		t.Fatalf("Distinguished: %v", err)
	}
	head := resp.GetTreeHead()
	if head == nil || head.GetTreeHead() == nil {
		t.Fatal("nil tree head")
	}
	sigs := head.GetTreeHead().GetSignatures()
	if len(sigs) != 1 {
		t.Fatalf("got %d signatures, want 1", len(sigs))
	}
	if string(sigs[0].GetAuditorPublicKey()) != string(pub) {
		t.Error("signer pub mismatch")
	}
}

func TestGRPCServer_Search_AciOnly(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	log := NewMemoryLog()
	var aci [16]byte
	aci[0] = 1
	_, _ = log.Append(aci[:], []byte("alice-identity-key"))
	c := newClient(t, log, priv)
	resp, err := c.Search(context.Background(), &ktpb.SearchRequest{
		Aci:            aci[:],
		AciIdentityKey: []byte("ack"),
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if string(resp.GetAci().GetOpening()) != "alice-identity-key" {
		t.Errorf("Opening = %q", resp.GetAci().GetOpening())
	}
}

func TestGRPCServer_Search_RejectsBadACI(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	c := newClient(t, NewMemoryLog(), priv)
	_, err := c.Search(context.Background(), &ktpb.SearchRequest{Aci: []byte{1, 2, 3}})
	if err == nil {
		t.Error("expected InvalidArgument for 3-byte ACI")
	}
}

func TestGRPCServer_Search_OptionalE164AndUsernameHash(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	log := NewMemoryLog()
	var aci [16]byte
	aci[0] = 2
	_, _ = log.Append(aci[:], []byte("aci-val"))
	_, _ = log.Append([]byte("+15551112222"), []byte("e164-val"))
	uh := make([]byte, 32)
	uh[31] = 0xAB
	_, _ = log.Append(uh, []byte("username-val"))

	c := newClient(t, log, priv)
	resp, err := c.Search(context.Background(), &ktpb.SearchRequest{
		Aci:            aci[:],
		AciIdentityKey: []byte("ack"),
		UsernameHash:   uh,
		E164SearchRequest: &ktpb.E164SearchRequest{
			E164: stringPtr("+15551112222"),
		},
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if string(resp.GetE164().GetOpening()) != "e164-val" {
		t.Errorf("E164 opening = %q", resp.GetE164().GetOpening())
	}
	if string(resp.GetUsernameHash().GetOpening()) != "username-val" {
		t.Errorf("UsernameHash opening = %q", resp.GetUsernameHash().GetOpening())
	}
}

func TestGRPCServer_Monitor(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	c := newClient(t, NewMemoryLog(), priv)
	resp, err := c.Monitor(context.Background(), &ktpb.MonitorRequest{})
	if err != nil {
		t.Fatalf("Monitor: %v", err)
	}
	if resp.GetTreeHead() == nil {
		t.Error("nil tree head from Monitor")
	}
}

func stringPtr(s string) *string { return &s }
