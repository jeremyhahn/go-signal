//go:build integration

// Package api hosts the Phase 4 verification gate.
//
// TestPhase4Topology is the in-process superset of the per-sub-phase
// e2e tests we shipped in 4.1–4.5. It stands up the wire surfaces of
// every Phase 4 binary in one process and drives the operator-facing
// flow:
//
//  1. registration-service creates a verification session for a new
//     E.164, sends a code through the stub transport, accepts the
//     code, returns a verified session.
//  2. signald's directory gRPC service streams the new account row
//     into cdsi's directory.
//  3. cdsi resolves the registered E.164 → PNI tuple over the
//     Noise NKhfs WebSocket.
//  4. storage-service accepts an encrypted manifest; signald's admin
//     client purges it.
//  5. svr2 admin DELETE purges the per-account secret-recovery row.
//  6. key-transparency appends a (search-key, identity-key) entry
//     and surfaces it through the manager → remote gRPC chain.
//
// The full docker-compose-deployed cluster runs the same sequence via
// `make integration-test`; this in-process variant verifies the
// cross-package wire stays glued together inside the regular CI loop.
package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"

	"github.com/coder/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"

	cdsipb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/cdsi"
	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
	dirsvc "github.com/jeremyhahn/go-signal/pkg/api/grpc/services/directory"
	"github.com/jeremyhahn/go-signal/pkg/attestation"
	"github.com/jeremyhahn/go-signal/pkg/cdsi"
	"github.com/jeremyhahn/go-signal/pkg/extservice/common"
	ktclient "github.com/jeremyhahn/go-signal/pkg/extservice/keytransparency"
	"github.com/jeremyhahn/go-signal/pkg/extservice/registration/inprocess"
	"github.com/jeremyhahn/go-signal/pkg/extservice/storage"
	"github.com/jeremyhahn/go-signal/pkg/extservice/svr"
	ktmgr "github.com/jeremyhahn/go-signal/pkg/keytransparency"
	ktserver "github.com/jeremyhahn/go-signal/pkg/keytransparency/server"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	memstorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/svr2"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// topology bundles the in-process equivalents of every Phase 4 binary
// plus the chat-server-side clients that bind them together.
type topology struct {
	// Registration-service (Phase 4.1).
	regClient    *inprocess.Client
	regTransport *captureTransport

	// Signald-side directory gRPC source + cdsi directory (Phase 4.3).
	directoryEntries *appendableMemorySource
	cdsiDirectory    *cdsi.MemoryDirectory
	cdsiWSURL        string
	cdsiAttester     *attestation.SoftwareAttester
	cdsiSecret       []byte
	dirConn          *grpc.ClientConn

	// SVR2 admin (Phase 4.2).
	svr2Store    *svr2.MemoryStorage
	svr2AdminURL string
	svr2Secret   []byte

	// Storage-service (Phase 4.4).
	storageStore *memstorage.MemoryManifestStore
	storageURL   string
	storageSec   []byte

	// Key-transparency (Phase 4.5).
	ktLog     *ktserver.MemoryLog
	ktManager *ktmgr.KeyTransparencyManager
}

// captureTransport records the verification codes the
// registration-service dispatches so the test driver can submit them.
type captureTransport struct {
	last string
}

func (c *captureTransport) SendCode(_ context.Context, _, code string, _ ...verification.SendOption) error {
	c.last = code
	return nil
}

func (c *captureTransport) Name() string { return "topology-capture" }

// appendableMemorySource is dirsvc.AccountSource with a mutable
// backing slice — the in-process equivalent of signald writing a new
// account row that the snapshot stream then picks up.
//
// The load gate (TestPhase5_FullTopologyUnderLoad) appends from 50
// goroutines at once, so the slice is guarded: an unsynchronized append
// both races and silently loses entries.
type appendableMemorySource struct {
	mu      sync.RWMutex
	entries []dirsvc.DirectoryEntry
}

// ListAll iterates a snapshot rather than the live slice, so a concurrent
// Append is neither blocked by nor visible to an in-flight walk, and fn
// never runs while the lock is held.
func (m *appendableMemorySource) ListAll(ctx context.Context, fn func(dirsvc.DirectoryEntry) error) error {
	m.mu.RLock()
	snapshot := make([]dirsvc.DirectoryEntry, len(m.entries))
	copy(snapshot, m.entries)
	m.mu.RUnlock()

	for _, e := range snapshot {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (m *appendableMemorySource) Append(e dirsvc.DirectoryEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
}

func buildTopology(t *testing.T) *topology {
	t.Helper()
	tp := &topology{}

	// 1) registration-service.
	tp.regTransport = &captureTransport{}
	regCore := core.NewService(
		verification.NewMemoryVerificationSessionStore(),
		tp.regTransport,
		core.Config{CodeLength: 6, FixedCode: "424242"},
	)
	t.Cleanup(regCore.Shutdown)
	tp.regClient = inprocess.New(regCore)

	// 2) Signald-side DirectoryService gRPC + cdsi WebSocket.
	tp.cdsiSecret = []byte("phase4-cdsi-secret")
	tp.directoryEntries = &appendableMemorySource{}
	dirLis := bufconn.Listen(1 << 20)
	dirGS := grpc.NewServer()
	dirpb.RegisterDirectoryServiceServer(dirGS, dirsvc.NewServer(tp.directoryEntries))
	go func() { _ = dirGS.Serve(dirLis) }()
	t.Cleanup(dirGS.Stop)
	dirConn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return dirLis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial directory: %v", err)
	}
	t.Cleanup(func() { _ = dirConn.Close() })
	tp.dirConn = dirConn

	tp.cdsiDirectory = cdsi.NewMemoryDirectory()
	tp.cdsiAttester, _ = attestation.NewSoftware(attestation.SoftwareConfig{})
	cdsiDisp := cdsi.NewDispatcher(tp.cdsiDirectory)
	cdsiMux := http.NewServeMux()
	cdsiMux.Handle("/v1/lookup", buildCDSIHandlerTopology(tp.cdsiAttester, cdsiDisp, tp.cdsiSecret))
	cdsiSrv := httptest.NewServer(cdsiMux)
	t.Cleanup(cdsiSrv.Close)
	tp.cdsiWSURL = "ws" + strings.TrimPrefix(cdsiSrv.URL, "http") + "/v1/lookup"

	// 3) SVR2 admin HTTP.
	tp.svr2Secret = []byte("phase4-svr2-secret")
	tp.svr2Store = svr2.NewMemoryStorage()
	adminMux := http.NewServeMux()
	adminMux.Handle("/v1/delete", buildAdminDelete(tp.svr2Secret, func(ctx context.Context, identity string) error {
		return tp.svr2Store.Delete(ctx, identity)
	}))
	adminSrv := httptest.NewServer(adminMux)
	t.Cleanup(adminSrv.Close)
	tp.svr2AdminURL = adminSrv.URL

	// 4) Storage-service HTTP.
	tp.storageSec = []byte("phase4-storage-secret")
	tp.storageStore = memstorage.NewMemoryManifestStore()
	storageMux := http.NewServeMux()
	storageMux.Handle("DELETE /v1/storage", buildAdminDelete(tp.storageSec, func(ctx context.Context, identity string) error {
		return tp.storageStore.DeleteAll(ctx, identity)
	}))
	storageSrv := httptest.NewServer(storageMux)
	t.Cleanup(storageSrv.Close)
	tp.storageURL = storageSrv.URL

	// 5) Key-transparency gRPC + signald-side manager.
	tp.ktLog = ktserver.NewMemoryLog()
	_, ktPriv, _ := ed25519.GenerateKey(nil)
	ktLis := bufconn.Listen(1 << 20)
	ktGS := grpc.NewServer()
	ktpb.RegisterKeyTransparencyQueryServiceServer(ktGS, ktserver.NewGRPCServer(tp.ktLog, ktPriv))
	go func() { _ = ktGS.Serve(ktLis) }()
	t.Cleanup(ktGS.Stop)
	ktConn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return ktLis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial KT: %v", err)
	}
	t.Cleanup(func() { _ = ktConn.Close() })
	ktRemote, _ := ktclient.New(ktclient.Config{Conn: ktConn})
	t.Cleanup(func() { _ = ktRemote.Close() })
	tp.ktManager = ktmgr.NewKeyTransparencyManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
	tp.ktManager.SetRemote(ktRemote)

	return tp
}

// buildAdminDelete is the shared HMAC-Basic admin handler shape used
// by svr2 and storage-service.
func buildAdminDelete(secret []byte, deleteFn func(context.Context, string) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := common.ValidateBasicAuth(r.Header.Get("Authorization"), secret)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := deleteFn(r.Context(), identity); err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func buildCDSIHandlerTopology(a attestation.Attester, disp *cdsi.Dispatcher, secret []byte) http.Handler {
	staticPub := a.PublicKey()
	staticPriv := a.(interface{ StaticPrivateKey() []byte }).StaticPrivateKey()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := common.ValidateBasicAuth(r.Header.Get("Authorization"), secret)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close(websocket.StatusInternalError, "closed") }()
		ev, err := a.Attest(r.Context(), staticPub)
		if err != nil {
			return
		}
		sess, err := cdsi.NewSession(cdsi.SessionConfig{
			Identity:         identity,
			StaticPrivateKey: staticPriv,
			StaticPublicKey:  staticPub,
			Evidence:         ev.Evidence,
			Endorsement:      ev.Endorsement,
			Dispatcher:       disp,
		})
		if err != nil {
			return
		}
		if err := writeTopoBin(r.Context(), conn, cdsi.MarshalFrame(sess.AttestationFrame())); err != nil {
			return
		}
		body, err := readTopoBin(r.Context(), conn)
		if err != nil {
			return
		}
		msg1, _ := cdsi.ParseFrame(body)
		msg2, err := sess.HandleHandshake(msg1)
		if err != nil {
			return
		}
		if err := writeTopoBin(r.Context(), conn, cdsi.MarshalFrame(msg2)); err != nil {
			return
		}
		for {
			body, err := readTopoBin(r.Context(), conn)
			if err != nil {
				return
			}
			in, _ := cdsi.ParseFrame(body)
			out, err := sess.HandleTransport(r.Context(), in)
			if err != nil {
				return
			}
			if err := writeTopoBin(r.Context(), conn, cdsi.MarshalFrame(out)); err != nil {
				return
			}
		}
	})
}

func writeTopoBin(ctx context.Context, c *websocket.Conn, b []byte) error {
	return c.Write(ctx, websocket.MessageBinary, b)
}

func readTopoBin(ctx context.Context, c *websocket.Conn) ([]byte, error) {
	_, b, err := c.Read(ctx)
	return b, err
}

func topoHMACAuth(identity string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(identity))
	pw := hex.EncodeToString(mac.Sum(nil))
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(identity+":"+pw))
}

// TestPhase4Topology is the Phase 4 verification gate.
func TestPhase4Topology(t *testing.T) {
	tp := buildTopology(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const e164 = "+15551234567"
	const accountUUID = "00000000-0000-0000-0000-000000000001"

	// Step 1: registration-service round-trip.
	sess, err := tp.regClient.CreateSession(ctx, e164)
	if err != nil {
		t.Fatalf("registration CreateSession: %v", err)
	}
	if _, err := tp.regClient.SendCode(ctx, sess.ID); err != nil {
		t.Fatalf("registration SendCode: %v", err)
	}
	if tp.regTransport.last == "" {
		t.Fatalf("transport did not capture a code")
	}
	verified, err := tp.regClient.SubmitCode(ctx, sess.ID, tp.regTransport.last)
	if err != nil {
		t.Fatalf("registration SubmitCode: %v", err)
	}
	if !verified.Verified {
		t.Error("session should be verified")
	}

	// Step 2: signald appends a directory row and cdsi streams it.
	var aci, pni [16]byte
	aci[0] = 0xAB
	pni[1] = 0xCD
	tp.directoryEntries.Append(dirsvc.DirectoryEntry{
		E164: 15551234567,
		ACI:  aci,
		PNI:  pni,
	})
	dirClient := dirpb.NewDirectoryServiceClient(tp.dirConn)
	if err := cdsi.LoadFromSignald(ctx, dirClient, tp.cdsiDirectory, 100); err != nil {
		t.Fatalf("cdsi LoadFromSignald: %v", err)
	}
	if tp.cdsiDirectory.Count() != 1 {
		t.Fatalf("cdsi directory count = %d", tp.cdsiDirectory.Count())
	}

	// Step 3: cdsi WebSocket lookup returns the PNI.
	headers := http.Header{}
	headers.Set("Authorization", topoHMACAuth(accountUUID, tp.cdsiSecret))
	c, _, err := websocket.Dial(ctx, tp.cdsiWSURL, &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatalf("cdsi dial: %v", err)
	}
	defer func() { _ = c.Close(websocket.StatusNormalClosure, "done") }()
	body, _ := readTopoBin(ctx, c)
	attFrame, _ := cdsi.ParseFrame(body)
	ev, end, _ := cdsi.ParseAttestation(attFrame.Body)
	staticPub, _, err := attestation.VerifySoftwareEvidence(ev, end)
	if err != nil {
		t.Fatalf("VerifySoftwareEvidence: %v", err)
	}
	uv, err := attest.NewNKhfsInitiator(staticPub)
	if err != nil {
		t.Fatalf("NewNKhfsInitiator: %v", err)
	}
	cli := uv.SkipRaftValidation()
	if err := writeTopoBin(ctx, c, cdsi.MarshalFrame(cdsi.Frame{Kind: cdsi.FrameHandshake1, Body: cli.InitialRequest()})); err != nil {
		t.Fatalf("write msg1: %v", err)
	}
	body, _ = readTopoBin(ctx, c)
	msg2Frame, _ := cdsi.ParseFrame(body)
	conn, err := cli.Complete(msg2Frame.Body)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	var e164Buf [8]byte
	binary.BigEndian.PutUint64(e164Buf[:], 15551234567)
	lookupReq := &cdsipb.ClientRequest{E164SBytes: e164Buf[:]}
	frame, _ := proto.Marshal(lookupReq)
	ct, _ := conn.Send(frame)
	if err := writeTopoBin(ctx, c, cdsi.MarshalFrame(cdsi.Frame{Kind: cdsi.FrameTransport, Body: ct})); err != nil {
		t.Fatalf("write lookup: %v", err)
	}
	body, _ = readTopoBin(ctx, c)
	respFrame, _ := cdsi.ParseFrame(body)
	plain, err := conn.Recv(respFrame.Body)
	if err != nil {
		t.Fatalf("conn.Recv: %v", err)
	}
	var lookupResp cdsipb.ClientResponse
	if err := proto.Unmarshal(plain, &lookupResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(lookupResp.E164PniAciTriples) != 40 {
		t.Fatalf("triple len = %d, want 40", len(lookupResp.E164PniAciTriples))
	}
	if !bytes.Equal(lookupResp.E164PniAciTriples[8:24], pni[:]) {
		t.Errorf("PNI bytes mismatch — full-topology directory wire is broken")
	}

	// Step 4: storage-service admin DELETE via the production client.
	if err := tp.storageStore.PutManifest(ctx, accountUUID, &securestorage.StorageManifest{Version: 1, Value: []byte("m")}); err != nil {
		t.Fatalf("storage seed: %v", err)
	}
	storageSecret, err := secrets.NewSecureStringFromBytes(append([]byte(nil), tp.storageSec...))
	if err != nil {
		t.Fatalf("seal storage shared secret: %v", err)
	}
	defer storageSecret.Destroy()
	storageAdmin, err := storage.NewHTTP(storage.HTTPConfig{BaseURL: tp.storageURL, SharedSecret: storageSecret})
	if err != nil {
		t.Fatalf("storage admin client: %v", err)
	}
	t.Cleanup(func() { _ = storageAdmin.Close() })
	if err := storageAdmin.DeleteStoredData(ctx, accountUUID); err != nil {
		t.Fatalf("storage DeleteStoredData: %v", err)
	}
	if _, err := tp.storageStore.GetManifest(ctx, accountUUID); err == nil {
		t.Error("storage manifest should be gone after admin delete")
	}

	// Step 5: svr2 admin DELETE via the production client.
	if err := tp.svr2Store.Put(ctx, accountUUID, &svr2.Record{Version: 1, MaxTries: 5}); err != nil {
		t.Fatalf("svr2 seed: %v", err)
	}
	svrSecret, err := secrets.NewSecureStringFromBytes(append([]byte(nil), tp.svr2Secret...))
	if err != nil {
		t.Fatalf("seal svr2 shared secret: %v", err)
	}
	defer svrSecret.Destroy()
	svrAdmin, err := svr.NewHTTP(svr.HTTPConfig{BaseURL: tp.svr2AdminURL, SharedSecret: svrSecret})
	if err != nil {
		t.Fatalf("svr2 admin client: %v", err)
	}
	t.Cleanup(func() { _ = svrAdmin.Close() })
	if err := svrAdmin.RemoveData(ctx, accountUUID); err != nil {
		t.Fatalf("svr2 RemoveData: %v", err)
	}
	if got, _ := tp.svr2Store.Count(ctx); got != 0 {
		t.Errorf("svr2 store count after delete = %d", got)
	}

	// Step 6: KT append + chat-server search proxy chain.
	if _, err := tp.ktLog.Append(aci[:], []byte("alice-identity-key")); err != nil {
		t.Fatalf("kt Append: %v", err)
	}
	ktResp, err := tp.ktManager.Search(ctx, &ktmgr.SearchRequest{})
	if err != nil {
		t.Fatalf("KT manager Search: %v", err)
	}
	if len(ktResp.Token) != ed25519.SignatureSize {
		t.Errorf("KT search token len = %d, want %d", len(ktResp.Token), ed25519.SignatureSize)
	}
}
