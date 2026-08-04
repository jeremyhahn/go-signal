//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"

	cdsipb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/cdsi"
	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
	dirsvc "github.com/jeremyhahn/go-signal/pkg/api/grpc/services/directory"
	"github.com/jeremyhahn/go-signal/pkg/attestation"
	"github.com/jeremyhahn/go-signal/pkg/cdsi"
)

// startCDSIInProcess spins up a signald directory gRPC server + a
// cdsi WebSocket handler in the same process. Returns the WS URL,
// the SoftwareAttester, and the in-memory directory for direct
// assertions.
func startCDSIInProcess(t *testing.T, sharedSecret string, dirEntries []dirsvc.DirectoryEntry) (wsURL string, att *attestation.SoftwareAttester, directory *cdsi.MemoryDirectory) {
	t.Helper()
	a, err := attestation.NewSoftware(attestation.SoftwareConfig{})
	if err != nil {
		t.Fatalf("NewSoftware: %v", err)
	}

	// Signald-side directory gRPC server.
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	dirpb.RegisterDirectoryServiceServer(gs, dirsvc.NewServer(dirsvc.NewMemorySource(dirEntries)))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	dir := cdsi.NewMemoryDirectory()
	if err := cdsi.LoadFromSignald(context.Background(), dirpb.NewDirectoryServiceClient(conn), dir, 100); err != nil {
		t.Fatalf("LoadFromSignald: %v", err)
	}
	disp := cdsi.NewDispatcher(dir)

	// cdsi WebSocket handler.
	wsMux := http.NewServeMux()
	wsMux.Handle("/v1/lookup", buildCDSIWSHandler(a, disp, []byte(sharedSecret)))
	wsSrv := httptest.NewServer(wsMux)
	t.Cleanup(wsSrv.Close)

	return "ws" + strings.TrimPrefix(wsSrv.URL, "http") + "/v1/lookup", a, dir
}

func buildCDSIWSHandler(a attestation.Attester, disp *cdsi.Dispatcher, secret []byte) http.Handler {
	staticPub := a.PublicKey()
	staticPriv := a.(interface{ StaticPrivateKey() []byte }).StaticPrivateKey()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := basicAuthHMACIdentity(r.Header.Get("Authorization"), secret)
		if identity == "" {
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
		if err := writeCDSIFrame(r.Context(), conn, sess.AttestationFrame()); err != nil {
			return
		}
		msg1Body, err := readCDSIBin(r.Context(), conn)
		if err != nil {
			return
		}
		msg1, _ := cdsi.ParseFrame(msg1Body)
		msg2, err := sess.HandleHandshake(msg1)
		if err != nil {
			return
		}
		if err := writeCDSIFrame(r.Context(), conn, msg2); err != nil {
			return
		}
		for {
			body, err := readCDSIBin(r.Context(), conn)
			if err != nil {
				return
			}
			in, _ := cdsi.ParseFrame(body)
			out, err := sess.HandleTransport(r.Context(), in)
			if err != nil {
				return
			}
			if err := writeCDSIFrame(r.Context(), conn, out); err != nil {
				return
			}
		}
	})
}

func basicAuthHMACIdentity(hdr string, secret []byte) string {
	const prefix = "Basic "
	if !strings.HasPrefix(hdr, prefix) {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(hdr[len(prefix):])
	if err != nil {
		return ""
	}
	sep := strings.IndexByte(string(raw), ':')
	if sep < 0 {
		return ""
	}
	identity := string(raw[:sep])
	password := string(raw[sep+1:])
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(identity))
	want := hex.EncodeToString(mac.Sum(nil))
	if password != want {
		return ""
	}
	return identity
}

func cdsiBasicAuth(identity string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(identity))
	pw := hex.EncodeToString(mac.Sum(nil))
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(identity+":"+pw))
}

func writeCDSIFrame(ctx context.Context, c *websocket.Conn, f cdsi.Frame) error {
	return c.Write(ctx, websocket.MessageBinary, cdsi.MarshalFrame(f))
}

func readCDSIBin(ctx context.Context, c *websocket.Conn) ([]byte, error) {
	_, b, err := c.Read(ctx)
	return b, err
}

func packE164sBE(nums ...uint64) []byte {
	out := make([]byte, len(nums)*8)
	for i, n := range nums {
		binary.BigEndian.PutUint64(out[i*8:], n)
	}
	return out
}

// TestCDSIE2E_FullLookupFlow exercises:
//
//  1. signald gRPC DirectoryService sync (cdsi loads its index)
//  2. WebSocket auth + attestation + Noise NKhfs handshake
//  3. Encrypted ClientRequest → ClientResponse with correct PNI bytes
//     for a registered number and zero bytes for an unregistered one.
func TestCDSIE2E_FullLookupFlow(t *testing.T) {
	const sharedSecret = "phase-4-3-cdsi-secret"
	var aliceACI, alicePNI [16]byte
	aliceACI[0] = 0xAB
	alicePNI[1] = 0xCD
	entries := []dirsvc.DirectoryEntry{
		{E164: 15551112222, ACI: aliceACI, PNI: alicePNI},
	}
	wsURL, att, dir := startCDSIInProcess(t, sharedSecret, entries)
	if dir.Count() != 1 {
		t.Fatalf("directory count after sync = %d", dir.Count())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	headers := http.Header{}
	headers.Set("Authorization", cdsiBasicAuth("alice-account-uuid", []byte(sharedSecret)))
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "done") })

	// Read attestation.
	body, err := readCDSIBin(ctx, c)
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	attFrame, _ := cdsi.ParseFrame(body)
	ev, end, err := cdsi.ParseAttestation(attFrame.Body)
	if err != nil {
		t.Fatalf("ParseAttestation: %v", err)
	}
	staticPub, _, err := attestation.VerifySoftwareEvidence(ev, end)
	if err != nil {
		t.Fatalf("VerifySoftwareEvidence: %v", err)
	}
	if !bytes.Equal(staticPub, att.PublicKey()) {
		t.Errorf("attested public key mismatch")
	}

	uv, err := attest.NewNKhfsInitiator(staticPub)
	if err != nil {
		t.Fatalf("NewNKhfsInitiator: %v", err)
	}
	cli := uv.SkipRaftValidation()
	if err := writeCDSIFrame(ctx, c, cdsi.Frame{Kind: cdsi.FrameHandshake1, Body: cli.InitialRequest()}); err != nil {
		t.Fatalf("write msg1: %v", err)
	}
	body, err = readCDSIBin(ctx, c)
	if err != nil {
		t.Fatalf("read msg2: %v", err)
	}
	msg2, _ := cdsi.ParseFrame(body)
	conn, err := cli.Complete(msg2.Body)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Encrypted lookup: known + unknown E.164.
	req := &cdsipb.ClientRequest{E164SBytes: packE164sBE(15551112222, 15559999000)}
	frame, _ := proto.Marshal(req)
	ct, _ := conn.Send(frame)
	if err := writeCDSIFrame(ctx, c, cdsi.Frame{Kind: cdsi.FrameTransport, Body: ct}); err != nil {
		t.Fatalf("write lookup: %v", err)
	}
	body, err = readCDSIBin(ctx, c)
	if err != nil {
		t.Fatalf("read lookup resp: %v", err)
	}
	respFrame, _ := cdsi.ParseFrame(body)
	plain, err := conn.Recv(respFrame.Body)
	if err != nil {
		t.Fatalf("conn.Recv: %v", err)
	}
	var resp cdsipb.ClientResponse
	if err := proto.Unmarshal(plain, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.E164PniAciTriples) != 80 {
		t.Fatalf("triples len = %d, want 80", len(resp.E164PniAciTriples))
	}
	// First triple: alice → PNI present, ACI absent.
	if !bytes.Equal(resp.E164PniAciTriples[8:24], alicePNI[:]) {
		t.Error("alice PNI mismatch")
	}
	var zero [16]byte
	if !bytes.Equal(resp.E164PniAciTriples[24:40], zero[:]) {
		t.Error("alice ACI should be zero without access-key proof")
	}
	// Second triple: unknown number → both UUIDs zero.
	if !bytes.Equal(resp.E164PniAciTriples[40+8:40+24], zero[:]) {
		t.Error("unknown PNI should be zero")
	}
}

// TestCDSIE2E_UnauthorizedRejected confirms the HMAC auth gate.
func TestCDSIE2E_UnauthorizedRejected(t *testing.T) {
	const sharedSecret = "auth-gate-test"
	wsURL, _, _ := startCDSIInProcess(t, sharedSecret, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	headers := http.Header{}
	headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:wrong")))
	_, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: headers})
	if err == nil {
		t.Fatal("expected dial failure on bad credentials")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401; got %v", resp)
	}
}
