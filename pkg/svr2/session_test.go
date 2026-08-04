package svr2

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"
	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

func newServerKeys(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	return priv, pub
}

func TestFrame_RoundTrip(t *testing.T) {
	f := Frame{Kind: FrameTransport, Body: []byte{1, 2, 3, 4}}
	wire := MarshalFrame(f)
	got, err := ParseFrame(wire)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if got.Kind != f.Kind || !bytes.Equal(got.Body, f.Body) {
		t.Errorf("round-trip mismatch: %+v vs %+v", got, f)
	}
}

func TestParseFrame_Empty(t *testing.T) {
	if _, err := ParseFrame(nil); err == nil {
		t.Error("expected error on empty frame")
	}
}

func TestAttestation_RoundTrip(t *testing.T) {
	ev := []byte("evidence-bytes")
	end := []byte("endorsement-bytes")
	wire := MarshalAttestation(ev, end)
	gotEv, gotEnd, err := ParseAttestation(wire)
	if err != nil {
		t.Fatalf("ParseAttestation: %v", err)
	}
	if !bytes.Equal(gotEv, ev) || !bytes.Equal(gotEnd, end) {
		t.Errorf("round-trip mismatch")
	}
}

func TestParseAttestation_BadInputs(t *testing.T) {
	if _, _, err := ParseAttestation(make([]byte, 2)); err == nil {
		t.Error("too-short input must error")
	}
	// Length prefix overflows.
	bad := []byte{0, 0, 0, 0xff, 0, 0, 0, 0}
	if _, _, err := ParseAttestation(bad); err == nil {
		t.Error("overflow length must error")
	}
}

func TestNewSession_Validation(t *testing.T) {
	priv, pub := newServerKeys(t)
	d := NewDispatcher(NewMemoryStorage())
	if _, err := NewSession(SessionConfig{}); err == nil {
		t.Error("expected error on missing Dispatcher")
	}
	if _, err := NewSession(SessionConfig{
		Dispatcher: d, StaticPrivateKey: make([]byte, 31), StaticPublicKey: pub, Identity: "x",
	}); err == nil {
		t.Error("expected error on short static priv")
	}
	if _, err := NewSession(SessionConfig{
		Dispatcher: d, StaticPrivateKey: priv, StaticPublicKey: pub,
	}); err == nil {
		t.Error("expected error on missing Identity")
	}
}

func TestSession_FullHandshakeAndTransport(t *testing.T) {
	priv, pub := newServerKeys(t)
	d := NewDispatcher(NewMemoryStorage())
	sess, err := NewSession(SessionConfig{
		Identity:         "alice",
		StaticPrivateKey: priv,
		StaticPublicKey:  pub,
		Evidence:         []byte("ev"),
		Endorsement:      []byte("end"),
		Dispatcher:       d,
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// Attestation frame contains both fields.
	att := sess.AttestationFrame()
	if att.Kind != FrameAttestation {
		t.Errorf("att kind = %d", att.Kind)
	}

	// Build a client-side message-1.
	uv, err := attest.NewNKhfsInitiator(pub)
	if err != nil {
		t.Fatalf("NewNKhfsInitiator: %v", err)
	}
	cliHandshake := uv.SkipRaftValidation()
	cliMsg1 := cliHandshake.InitialRequest()

	// HandleHandshake rejects non-handshake frames.
	if _, err := sess.HandleHandshake(Frame{Kind: FrameTransport}); err == nil {
		t.Error("expected error on wrong handshake frame kind")
	}

	// Run the handshake.
	msg1Frame := Frame{Kind: FrameHandshake1, Body: cliMsg1}
	msg2Frame, err := sess.HandleHandshake(msg1Frame)
	if err != nil {
		t.Fatalf("HandleHandshake: %v", err)
	}
	if msg2Frame.Kind != FrameHandshake2 {
		t.Errorf("msg2 kind = %d", msg2Frame.Kind)
	}
	conn, err := cliHandshake.Complete(msg2Frame.Body)
	if err != nil {
		t.Fatalf("client Complete: %v", err)
	}
	if !bytes.Equal(conn.HandshakeHash, sess.HandshakeHash()) {
		t.Error("handshake hash mismatch")
	}

	// Transport: client encrypts a Create request; server dispatches.
	createReq := &svrpb.Request4{Inner: &svrpb.Request4_Create_{
		Create: &svrpb.Request4_Create{
			Version: 1, MaxTries: 3,
			OprfSecretshare: []byte{1, 2}, AuthCommitment: []byte{3, 4},
			EncryptionSecretshare: []byte{5, 6}, ZeroSecretshare: []byte{7, 8},
		}}}
	plaintext, _ := proto.Marshal(createReq)
	clientCT, err := conn.Send(plaintext)
	if err != nil {
		t.Fatalf("conn.Send: %v", err)
	}
	resp, err := sess.HandleTransport(context.Background(), Frame{Kind: FrameTransport, Body: clientCT})
	if err != nil {
		t.Fatalf("HandleTransport: %v", err)
	}
	respPlain, err := conn.Recv(resp.Body)
	if err != nil {
		t.Fatalf("conn.Recv: %v", err)
	}
	var rp svrpb.Response4
	if err := proto.Unmarshal(respPlain, &rp); err != nil {
		t.Fatalf("unmarshal resp: %v", err)
	}
	if rp.GetCreate().Status != svrpb.Response4_OK {
		t.Errorf("Create status = %v", rp.GetCreate().Status)
	}
}

func TestSession_TransportBeforeHandshakeRejected(t *testing.T) {
	priv, pub := newServerKeys(t)
	d := NewDispatcher(NewMemoryStorage())
	sess, _ := NewSession(SessionConfig{
		Identity:         "alice",
		StaticPrivateKey: priv,
		StaticPublicKey:  pub,
		Dispatcher:       d,
	})
	_, err := sess.HandleTransport(context.Background(), Frame{Kind: FrameTransport, Body: []byte("x")})
	if err == nil {
		t.Error("expected error on transport before handshake")
	}
}

func TestHandleHandshake_AlreadyDone(t *testing.T) {
	priv, pub := newServerKeys(t)
	d := NewDispatcher(NewMemoryStorage())
	sess, _ := NewSession(SessionConfig{
		Identity:         "bob",
		StaticPrivateKey: priv,
		StaticPublicKey:  pub,
		Dispatcher:       d,
	})

	// Complete a successful handshake first.
	uv, _ := attest.NewNKhfsInitiator(pub)
	hs := uv.SkipRaftValidation()
	msg1Frame := Frame{Kind: FrameHandshake1, Body: hs.InitialRequest()}
	if _, err := sess.HandleHandshake(msg1Frame); err != nil {
		t.Fatalf("first HandleHandshake: %v", err)
	}

	// Attempt a second handshake → must fail.
	_, err := sess.HandleHandshake(msg1Frame)
	if err == nil {
		t.Error("expected error on second HandleHandshake (already done)")
	}
}

func TestHandleTransport_WrongFrameKind(t *testing.T) {
	priv, pub := newServerKeys(t)
	d := NewDispatcher(NewMemoryStorage())
	sess, _ := NewSession(SessionConfig{
		Identity:         "carol",
		StaticPrivateKey: priv,
		StaticPublicKey:  pub,
		Dispatcher:       d,
	})

	// Complete handshake.
	uv, _ := attest.NewNKhfsInitiator(pub)
	hs := uv.SkipRaftValidation()
	msg1Frame := Frame{Kind: FrameHandshake1, Body: hs.InitialRequest()}
	msg2Frame, err := sess.HandleHandshake(msg1Frame)
	if err != nil {
		t.Fatalf("HandleHandshake: %v", err)
	}
	if _, err := hs.Complete(msg2Frame.Body); err != nil {
		t.Fatalf("client Complete: %v", err)
	}

	// Now send a non-FrameTransport frame — must error.
	_, err = sess.HandleTransport(context.Background(), Frame{Kind: FrameHandshake1, Body: []byte{1, 2, 3}})
	if err == nil {
		t.Error("expected error for wrong frame kind in HandleTransport")
	}
}

func TestParseAttestation_TrailingBytes(t *testing.T) {
	ev := []byte("evidence")
	end := []byte("endorsement")
	wire := MarshalAttestation(ev, end)
	// Append trailing garbage.
	wire = append(wire, 0xFF)
	_, _, err := ParseAttestation(wire)
	if err == nil {
		t.Error("expected error for attestation buffer with trailing bytes")
	}
}

func TestReadUint32BE_ShortBuffer(t *testing.T) {
	// bytes.NewReader with fewer than 4 bytes → readUint32BE must fail.
	r := bytes.NewReader([]byte{1, 2})
	_, err := readUint32BE(r)
	if err == nil {
		t.Error("expected error from readUint32BE on short buffer")
	}
}

func TestParseAttestation_LargeEvLength(t *testing.T) {
	// Evidence length exceeds remaining bytes.
	buf := []byte{0, 0, 0, 10, 0, 0, 0, 0} // evLen=10, no bytes follow
	_, _, err := ParseAttestation(buf)
	if err == nil {
		t.Error("expected error when evidence length exceeds buffer")
	}
}

func TestParseAttestation_EndLenReadError(t *testing.T) {
	// Wire: evLen=2, ev=[a,b], then only 3 bytes remain for endLen read (need 4) → error.
	buf := []byte{0, 0, 0, 2, 'a', 'b', 0, 0, 0}
	_, _, err := ParseAttestation(buf)
	if err == nil {
		t.Error("expected error when endLen field is truncated")
	}
}

func TestParseAttestation_EndBodyReadError(t *testing.T) {
	// Wire: evLen=0, ev=[], endLen=5, only 2 end bytes follow → io.ReadFull error.
	buf := []byte{0, 0, 0, 0, 0, 0, 0, 5, 'a', 'b'}
	_, _, err := ParseAttestation(buf)
	if err == nil {
		t.Error("expected error when endorsement body is truncated")
	}
}

func TestHandleHandshake_InvalidMessage1_SetsStalled(t *testing.T) {
	priv, pub := newServerKeys(t)
	d := NewDispatcher(NewMemoryStorage())
	sess, err := NewSession(SessionConfig{
		Identity:         "dave",
		StaticPrivateKey: priv,
		StaticPublicKey:  pub,
		Dispatcher:       d,
	})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	// Garbage message-1 body — ProcessMessage1 must fail, setting s.stalled.
	_, err = sess.HandleHandshake(Frame{Kind: FrameHandshake1, Body: []byte{0x01, 0x02, 0x03}})
	if err == nil {
		t.Error("expected error for invalid handshake message-1")
	}
	if !sess.stalled {
		t.Error("expected sess.stalled = true after failed ProcessMessage1")
	}
}

func TestHandleTransport_GarbageCiphertext_ReturnsDecryptError(t *testing.T) {
	priv, pub := newServerKeys(t)
	d := NewDispatcher(NewMemoryStorage())
	sess, _ := NewSession(SessionConfig{
		Identity:         "eve",
		StaticPrivateKey: priv,
		StaticPublicKey:  pub,
		Dispatcher:       d,
	})

	// Complete handshake.
	uv, _ := attest.NewNKhfsInitiator(pub)
	hs := uv.SkipRaftValidation()
	msg2, err := sess.HandleHandshake(Frame{Kind: FrameHandshake1, Body: hs.InitialRequest()})
	if err != nil {
		t.Fatalf("HandleHandshake: %v", err)
	}
	if _, err := hs.Complete(msg2.Body); err != nil {
		t.Fatalf("client Complete: %v", err)
	}

	// Send garbage transport body → Decrypt must fail.
	_, err = sess.HandleTransport(context.Background(), Frame{Kind: FrameTransport, Body: []byte{0xDE, 0xAD, 0xBE, 0xEF}})
	if err == nil {
		t.Error("expected decrypt error for garbage transport ciphertext")
	}
}
