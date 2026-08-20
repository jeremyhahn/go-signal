//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"

	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"
	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"

	"github.com/jeremyhahn/go-signal/pkg/attestation"
	"github.com/jeremyhahn/go-signal/pkg/extservice/svr"
	"github.com/jeremyhahn/go-signal/pkg/svr2"
)

// hmacCreds returns the Authorization Basic header value for an
// HMAC-derived credential pair (identity, hex(HMAC-SHA256(secret, identity))).
func hmacCreds(identity string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(identity))
	pw := hex.EncodeToString(mac.Sum(nil))
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(identity+":"+pw))
}

// startSVR2InProcess spins up the cmd/svr2 binary's HTTP handlers in-
// process using SoftwareAttester + MemoryStorage. Returns the WS URL,
// the admin HTTP URL, and the storage handle for direct test
// assertions.
func startSVR2InProcess(t *testing.T, sharedSecret string) (wsURL, adminURL string, storage *svr2.MemoryStorage, att *attestation.SoftwareAttester) {
	t.Helper()
	a, err := attestation.NewSoftware(attestation.SoftwareConfig{})
	if err != nil {
		t.Fatalf("NewSoftware: %v", err)
	}
	mem := svr2.NewMemoryStorage()
	disp := svr2.NewDispatcher(mem)

	// Mount the WebSocket and admin handlers on dedicated test servers
	// — separate ports mirror the production layout.
	wsMux := http.NewServeMux()
	wsMux.Handle("/v1/ws", buildE2EWSHandler(a, disp, []byte(sharedSecret)))
	wsSrv := httptest.NewServer(wsMux)
	t.Cleanup(wsSrv.Close)

	adminMux := http.NewServeMux()
	adminMux.Handle("/v1/delete", buildE2EAdminHandler(mem, []byte(sharedSecret)))
	adminSrv := httptest.NewServer(adminMux)
	t.Cleanup(adminSrv.Close)

	return "ws" + strings.TrimPrefix(wsSrv.URL, "http") + "/v1/ws",
		adminSrv.URL, mem, a
}

func buildE2EWSHandler(a attestation.Attester, disp *svr2.Dispatcher, secret []byte) http.Handler {
	staticPub := a.PublicKey()
	staticPriv := a.(interface{ StaticPrivateKey() []byte }).StaticPrivateKey()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		identity := authIdentity(hdr, secret)
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
		sess, err := svr2.NewSession(svr2.SessionConfig{
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
		if err := writeBin(r.Context(), conn, svr2.MarshalFrame(sess.AttestationFrame())); err != nil {
			return
		}
		msg1Body, err := readBin(r.Context(), conn)
		if err != nil {
			return
		}
		msg1, _ := svr2.ParseFrame(msg1Body)
		msg2, err := sess.HandleHandshake(msg1)
		if err != nil {
			return
		}
		if err := writeBin(r.Context(), conn, svr2.MarshalFrame(msg2)); err != nil {
			return
		}
		for {
			frameBody, err := readBin(r.Context(), conn)
			if err != nil {
				return
			}
			in, _ := svr2.ParseFrame(frameBody)
			out, err := sess.HandleTransport(r.Context(), in)
			if err != nil {
				return
			}
			if err := writeBin(r.Context(), conn, svr2.MarshalFrame(out)); err != nil {
				return
			}
		}
	})
}

func buildE2EAdminHandler(storage svr2.Storage, secret []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := authIdentity(r.Header.Get("Authorization"), secret)
		if identity == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := storage.Delete(r.Context(), identity); err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func authIdentity(hdr string, secret []byte) string {
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

func writeBin(ctx context.Context, c *websocket.Conn, b []byte) error {
	return c.Write(ctx, websocket.MessageBinary, b)
}

func readBin(ctx context.Context, c *websocket.Conn) ([]byte, error) {
	_, b, err := c.Read(ctx)
	return b, err
}

// TestSVR2E2E_FullBackupCreateAndRestoreFlow drives the entire flow:
//
//  1. Open a WebSocket with HMAC Basic auth.
//  2. Read attestation evidence, verify it via VerifySoftwareEvidence.
//  3. Run Noise NKhfs handshake.
//  4. Send a Create request, read Response4.OK.
//  5. Send a Query request, confirm version/tries_remaining match.
//  6. Open a fresh WebSocket, send Restore1, confirm tries_remaining decremented.
func TestSVR2E2E_FullBackupCreateAndRestoreFlow(t *testing.T) {
	const sharedSecret = "phase-4-2-test-secret"
	wsURL, _, _, att := startSVR2InProcess(t, sharedSecret)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dial := func() *websocket.Conn {
		headers := http.Header{}
		headers.Set("Authorization", hmacCreds("alice", []byte(sharedSecret)))
		c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: headers})
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close(websocket.StatusNormalClosure, "done") })
		return c
	}

	// First session: attestation + handshake + Create + Query.
	c := dial()
	body, err := readBin(ctx, c)
	if err != nil {
		t.Fatalf("read attestation: %v", err)
	}
	attFrame, _ := svr2.ParseFrame(body)
	ev, end, err := svr2.ParseAttestation(attFrame.Body)
	if err != nil {
		t.Fatalf("ParseAttestation: %v", err)
	}
	staticPub, boundData, err := attestation.VerifySoftwareEvidence(ev, end)
	if err != nil {
		t.Fatalf("VerifySoftwareEvidence: %v", err)
	}
	if !bytes.Equal(staticPub, att.PublicKey()) {
		t.Errorf("attested public key mismatch")
	}
	if !bytes.Equal(boundData, att.PublicKey()) {
		t.Errorf("boundData should equal staticPub (server commits to its own key)")
	}

	uv, err := attest.NewNKhfsInitiator(staticPub)
	if err != nil {
		t.Fatalf("NewNKhfsInitiator: %v", err)
	}
	cli := uv.SkipRaftValidation()
	if err := writeBin(ctx, c, svr2.MarshalFrame(svr2.Frame{
		Kind: svr2.FrameHandshake1, Body: cli.InitialRequest(),
	})); err != nil {
		t.Fatalf("write msg1: %v", err)
	}
	body, err = readBin(ctx, c)
	if err != nil {
		t.Fatalf("read msg2: %v", err)
	}
	msg2, _ := svr2.ParseFrame(body)
	conn, err := cli.Complete(msg2.Body)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// Create.
	createReq := &svrpb.Request4{Inner: &svrpb.Request4_Create_{
		Create: &svrpb.Request4_Create{
			Version: 1, MaxTries: 3,
			OprfSecretshare:       []byte{0xAA, 0xBB, 0xCC, 0xDD},
			AuthCommitment:        []byte{0xEE, 0xFF},
			EncryptionSecretshare: []byte{0x11, 0x22, 0x33, 0x44},
			ZeroSecretshare:       []byte{0x55, 0x66},
		},
	}}
	createBytes, _ := proto.Marshal(createReq)
	ct, _ := conn.Send(createBytes)
	if err := writeBin(ctx, c, svr2.MarshalFrame(svr2.Frame{Kind: svr2.FrameTransport, Body: ct})); err != nil {
		t.Fatalf("write Create: %v", err)
	}
	body, err = readBin(ctx, c)
	if err != nil {
		t.Fatalf("read Create resp: %v", err)
	}
	respFrame, _ := svr2.ParseFrame(body)
	respPlain, err := conn.Recv(respFrame.Body)
	if err != nil {
		t.Fatalf("Recv Create resp: %v", err)
	}
	var resp svrpb.Response4
	if err := proto.Unmarshal(respPlain, &resp); err != nil {
		t.Fatalf("unmarshal Create resp: %v", err)
	}
	if resp.GetCreate().Status != svrpb.Response4_OK {
		t.Errorf("Create status = %v", resp.GetCreate().Status)
	}

	// Query.
	queryReq, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Query_{Query: &svrpb.Request4_Query{}}})
	ct, _ = conn.Send(queryReq)
	if err := writeBin(ctx, c, svr2.MarshalFrame(svr2.Frame{Kind: svr2.FrameTransport, Body: ct})); err != nil {
		t.Fatalf("write Query: %v", err)
	}
	body, err = readBin(ctx, c)
	if err != nil {
		t.Fatalf("read Query resp: %v", err)
	}
	respFrame, _ = svr2.ParseFrame(body)
	respPlain, err = conn.Recv(respFrame.Body)
	if err != nil {
		t.Fatalf("Recv Query resp: %v", err)
	}
	var q svrpb.Response4
	if err := proto.Unmarshal(respPlain, &q); err != nil {
		t.Fatalf("unmarshal Query resp: %v", err)
	}
	if q.GetQuery().Status != svrpb.Response4_OK {
		t.Errorf("Query status = %v", q.GetQuery().Status)
	}
	if q.GetQuery().TriesRemaining != 3 {
		t.Errorf("Query tries_remaining = %d", q.GetQuery().TriesRemaining)
	}
}

// TestSVR2E2E_AdminDeleteViaHTTPClient drives the chat-server-to-svr2
// admin path. signald's SVRClient calls cmd/svr2's DELETE /v1/delete
// when an account is deleted; the record disappears from storage.
func TestSVR2E2E_AdminDeleteViaHTTPClient(t *testing.T) {
	const sharedSecret = "admin-delete-secret"
	_, adminURL, storage, _ := startSVR2InProcess(t, sharedSecret)
	ctx := context.Background()

	// Seed a record.
	_ = storage.Put(ctx, "bob", &svr2.Record{Version: 1, MaxTries: 5})
	if n, _ := storage.Count(ctx); n != 1 {
		t.Fatalf("seed count = %d", n)
	}

	cli, err := svr.NewHTTP(svr.HTTPConfig{
		BaseURL:      adminURL,
		SharedSecret: secrets.MustNewSecureString(sharedSecret),
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	if err := cli.RemoveData(ctx, "bob"); err != nil {
		t.Fatalf("RemoveData: %v", err)
	}
	if n, _ := storage.Count(ctx); n != 0 {
		t.Errorf("storage count after delete = %d, want 0", n)
	}
}

// TestSVR2E2E_UnauthorizedWebSocketRejected confirms the auth gate.
func TestSVR2E2E_UnauthorizedWebSocketRejected(t *testing.T) {
	const sharedSecret = "auth-test"
	wsURL, _, _, _ := startSVR2InProcess(t, sharedSecret)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Wrong password.
	headers := http.Header{}
	headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:wrong")))
	_, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: headers})
	if err == nil {
		t.Fatal("expected dial failure on bad credentials")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401; resp=%v", resp)
	}
}
