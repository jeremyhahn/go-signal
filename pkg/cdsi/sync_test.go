package cdsi

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
	dirsvc "github.com/jeremyhahn/go-signal/pkg/api/grpc/services/directory"
)

func newDirectoryGRPCStub(t *testing.T, source dirsvc.AccountSource) dirpb.DirectoryServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	dirpb.RegisterDirectoryServiceServer(gs, dirsvc.NewServer(source))
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

func TestLoadFromSignald_PopulatesDirectory(t *testing.T) {
	var aci, pni [16]byte
	aci[0] = 0xAB
	pni[1] = 0xCD
	source := dirsvc.NewMemorySource([]dirsvc.DirectoryEntry{
		{E164: 15551112222, ACI: aci, PNI: pni},
		{E164: 15552223333, PNI: pni},
	})
	client := newDirectoryGRPCStub(t, source)
	dir := NewMemoryDirectory()
	if err := LoadFromSignald(context.Background(), client, dir, 10); err != nil {
		t.Fatalf("LoadFromSignald: %v", err)
	}
	if dir.Count() != 2 {
		t.Errorf("Count = %d, want 2", dir.Count())
	}
	if entry, ok := dir.Lookup(15551112222); !ok {
		t.Error("missing entry")
	} else if entry.ACI != aci {
		t.Errorf("ACI mismatch")
	}
}

func TestLoadFromSignald_ValidationErrors(t *testing.T) {
	if err := LoadFromSignald(context.Background(), nil, NewMemoryDirectory(), 10); err == nil {
		t.Error("expected error on nil client")
	}
	c := newDirectoryGRPCStub(t, dirsvc.NewMemorySource(nil))
	if err := LoadFromSignald(context.Background(), c, nil, 10); err == nil {
		t.Error("expected error on nil directory")
	}
}
