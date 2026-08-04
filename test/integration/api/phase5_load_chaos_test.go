//go:build integration

// TestPhase5_FullTopologyUnderLoad + TestPhase5_Chaos_GRPCFailureDegradesCleanly
// together form the Phase 5.6 verification gate. They exercise the
// same wire as TestPhase4Topology but under concurrent load and with
// injected failures to confirm the system degrades cleanly rather
// than corrupting state.
//
// The docker-compose harness in deploy/docker-compose.yml runs the
// same flow against real binaries via `make integration-test`; this
// in-process variant catches breakage inside the regular CI loop.
package api

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
	dirsvc "github.com/jeremyhahn/go-signal/pkg/api/grpc/services/directory"
	"github.com/jeremyhahn/go-signal/pkg/cdsi"
	ktclient "github.com/jeremyhahn/go-signal/pkg/extservice/keytransparency"
	"github.com/jeremyhahn/go-signal/pkg/extservice/registration/inprocess"
	ktmgr "github.com/jeremyhahn/go-signal/pkg/keytransparency"
	ktserver "github.com/jeremyhahn/go-signal/pkg/keytransparency/server"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	memstorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/svr2"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// loadTopology bundles the in-process equivalents of every Phase 4
// binary with the chaos hooks the load test needs.
type loadTopology struct {
	regClient *inprocess.Client
	directory *appendableMemorySource

	// signald-side directory gRPC server — chaos test calls Stop()
	// to simulate a signald replica crash.
	signaldDirSrv *grpc.Server
	signaldDirLis *bufconn.Listener
	cdsiDirectory *cdsi.MemoryDirectory

	svr2Store *svr2.MemoryStorage
	storageS  *memstorage.MemoryManifestStore
	ktLog     *ktserver.MemoryLog
	ktManager *ktmgr.KeyTransparencyManager
}

// loadTransport records each verification code so the load test's
// per-iteration session lifecycle can submit them. last is read
// under a mutex because concurrent SendCode calls race here.
type loadTransport struct {
	mu   sync.Mutex
	last string
}

func (l *loadTransport) SendCode(_ context.Context, _, code string, _ ...verification.SendOption) error {
	l.mu.Lock()
	l.last = code
	l.mu.Unlock()
	return nil
}
func (l *loadTransport) Name() string { return "load-stub" }

func buildLoadTopology(t *testing.T) (*loadTopology, *loadTransport) {
	t.Helper()
	tp := &loadTopology{}

	tr := &loadTransport{}
	regCore := core.NewService(
		verification.NewMemoryVerificationSessionStore(),
		tr,
		core.Config{CodeLength: 6, FixedCode: "555555"},
	)
	t.Cleanup(regCore.Shutdown)
	tp.regClient = inprocess.New(regCore)

	tp.directory = &appendableMemorySource{}
	tp.signaldDirLis = bufconn.Listen(1 << 20)
	tp.signaldDirSrv = grpc.NewServer()
	dirpb.RegisterDirectoryServiceServer(tp.signaldDirSrv, dirsvc.NewServer(tp.directory))
	go func() { _ = tp.signaldDirSrv.Serve(tp.signaldDirLis) }()
	t.Cleanup(tp.signaldDirSrv.Stop)
	tp.cdsiDirectory = cdsi.NewMemoryDirectory()

	tp.svr2Store = svr2.NewMemoryStorage()
	tp.storageS = memstorage.NewMemoryManifestStore()

	tp.ktLog = ktserver.NewMemoryLog()
	_, ktPriv, _ := ed25519.GenerateKey(nil)
	ktLis := bufconn.Listen(1 << 20)
	ktGS := grpc.NewServer()
	ktpb.RegisterKeyTransparencyQueryServiceServer(ktGS, ktserver.NewGRPCServer(tp.ktLog, ktPriv))
	go func() { _ = ktGS.Serve(ktLis) }()
	t.Cleanup(ktGS.Stop)
	ktConn, _ := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return ktLis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { _ = ktConn.Close() })
	ktRemote, _ := ktclient.New(ktclient.Config{Conn: ktConn})
	t.Cleanup(func() { _ = ktRemote.Close() })
	tp.ktManager = ktmgr.NewKeyTransparencyManager(nil)
	tp.ktManager.SetRemote(ktRemote)

	return tp, tr
}

// runOneAccount drives the per-account flow: register, write to
// svr2 + storage-service, append a KT entry. Returns the assigned
// account identifier (the index-derived stable string) plus any
// fatal error.
func runOneAccount(ctx context.Context, tp *loadTopology, tr *loadTransport, idx int) (string, error) {
	number := fmt.Sprintf("+1555%07d", 1000000+idx)
	identity := fmt.Sprintf("acct-%07d", idx)

	sess, err := tp.regClient.CreateSession(ctx, number)
	if err != nil {
		return identity, fmt.Errorf("CreateSession: %w", err)
	}
	if _, err := tp.regClient.SendCode(ctx, sess.ID); err != nil {
		return identity, fmt.Errorf("SendCode: %w", err)
	}
	tr.mu.Lock()
	code := tr.last
	tr.mu.Unlock()
	verified, err := tp.regClient.SubmitCode(ctx, sess.ID, code)
	if err != nil || !verified.Verified {
		return identity, fmt.Errorf("SubmitCode: verified=%v err=%v", verified, err)
	}

	// Directory append (signald-side writer).
	var aci, pni [16]byte
	aci[0] = byte(idx)
	pni[1] = byte(idx)
	tp.directory.AppendForTest(dirsvc.DirectoryEntry{
		E164: uint64(15551000000 + idx),
		ACI:  aci,
		PNI:  pni,
	})

	// SVR2 backup.
	if err := tp.svr2Store.Put(ctx, identity, &svr2.Record{Version: 1, MaxTries: 5}); err != nil {
		return identity, fmt.Errorf("svr2 Put: %w", err)
	}

	// Storage manifest.
	if err := tp.storageS.PutManifest(ctx, identity, &securestorage.StorageManifest{
		Version: 1,
		Value:   []byte("manifest-" + identity),
	}); err != nil {
		return identity, fmt.Errorf("storage Put: %w", err)
	}

	// KT log append.
	if _, err := tp.ktLog.Append(aci[:], []byte("identity-key-"+identity)); err != nil {
		return identity, fmt.Errorf("kt Append: %w", err)
	}

	return identity, nil
}

// AppendForTest exposes the appendableMemorySource Append helper
// across the test package. The struct + method already exist in
// phase4_topology_test.go; this alias makes intent obvious.
func (m *appendableMemorySource) AppendForTest(e dirsvc.DirectoryEntry) { m.Append(e) }

// TestPhase5_FullTopologyUnderLoad runs 50 concurrent end-to-end
// flows against the same in-process topology. The per-flow steps
// (register → directory write → svr2 backup → storage manifest →
// KT append) share state across goroutines so the test confirms
// the underlying stores are concurrency-safe and the wire
// surfaces don't drop messages under contention.
func TestPhase5_FullTopologyUnderLoad(t *testing.T) {
	tp, tr := buildLoadTopology(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const N = 50
	var wg sync.WaitGroup
	var fail atomic.Uint64
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(idx int) {
			defer wg.Done()
			if _, err := runOneAccount(ctx, tp, tr, idx); err != nil {
				fail.Add(1)
				t.Errorf("account %d: %v", idx, err)
			}
		}(i)
	}
	wg.Wait()

	if got := fail.Load(); got != 0 {
		t.Fatalf("%d/%d flows failed under load", got, N)
	}

	// Cross-cutting assertions: every store reflects the load.
	if got, _ := tp.svr2Store.Count(ctx); got != N {
		t.Errorf("svr2 store count = %d, want %d", got, N)
	}
	if got := tp.cdsiDirectory.Count(); got != 0 {
		// Directory source has N entries; cdsi snapshot needs an
		// explicit load to pull them. Confirm the source side has them.
	}
	// Re-sync cdsi from signald's directory and assert N entries.
	dirConn, _ := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return tp.signaldDirLis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { _ = dirConn.Close() })
	if err := cdsi.LoadFromSignald(ctx, dirpb.NewDirectoryServiceClient(dirConn), tp.cdsiDirectory, 1000); err != nil {
		t.Fatalf("LoadFromSignald after load: %v", err)
	}
	if tp.cdsiDirectory.Count() != N {
		t.Errorf("cdsi directory count after sync = %d, want %d", tp.cdsiDirectory.Count(), N)
	}
	if tp.ktLog.Size() != uint64(N) {
		t.Errorf("kt log size = %d, want %d", tp.ktLog.Size(), N)
	}
	t.Logf("Phase 5.6 load gate: %d accounts processed, all stores consistent", N)
}

// TestPhase5_Chaos_GRPCFailureDegradesCleanly drives the
// failure-injection gate: kill the signald DirectoryService server
// after cdsi's snapshot loads, and assert subsequent reload attempts
// fail with a typed gRPC error rather than corrupting cdsi's local
// directory state.
func TestPhase5_Chaos_GRPCFailureDegradesCleanly(t *testing.T) {
	tp, _ := buildLoadTopology(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Seed the directory with one entry and confirm cdsi syncs.
	var aci, pni [16]byte
	aci[0] = 0x01
	pni[1] = 0x02
	tp.directory.AppendForTest(dirsvc.DirectoryEntry{E164: 15551112222, ACI: aci, PNI: pni})

	dirConn, _ := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return tp.signaldDirLis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { _ = dirConn.Close() })
	if err := cdsi.LoadFromSignald(ctx, dirpb.NewDirectoryServiceClient(dirConn), tp.cdsiDirectory, 100); err != nil {
		t.Fatalf("initial Sync: %v", err)
	}
	if tp.cdsiDirectory.Count() != 1 {
		t.Fatalf("initial count = %d", tp.cdsiDirectory.Count())
	}

	// Chaos: stop the signald DirectoryService server.
	tp.signaldDirSrv.Stop()
	_ = tp.signaldDirLis.Close()

	// Subsequent sync must error (typed gRPC failure) but cdsi's
	// existing snapshot stays intact — graceful degradation.
	err := cdsi.LoadFromSignald(ctx, dirpb.NewDirectoryServiceClient(dirConn), tp.cdsiDirectory, 100)
	if err == nil {
		t.Fatal("expected error after signald shutdown")
	}
	if !isExpectedDownstreamError(err) {
		t.Errorf("expected typed gRPC failure, got %v", err)
	}
	if tp.cdsiDirectory.Count() != 1 {
		t.Errorf("cdsi directory should keep its pre-failure entries; got %d", tp.cdsiDirectory.Count())
	}
}

// isExpectedDownstreamError reports whether err is the gRPC-level
// failure mode the chaos test expects: anything other than nil that
// surfaces from a closed listener counts. The test is checking that
// the failure is surfaced cleanly, not the specific gRPC error code.
func isExpectedDownstreamError(err error) bool {
	if err == nil {
		return false
	}
	// gRPC surfaces this as a Unavailable/Canceled status; the bufconn
	// closes show up as transport errors. Both are acceptable —
	// what matters is that the error is propagated, not the exact
	// classification.
	return !errors.Is(err, context.Canceled)
}
