package cdsi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"

	cdsipb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/cdsi"
)

func newServerKeys(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	return priv, pub
}

func TestFrame_RoundTrip(t *testing.T) {
	f := Frame{Kind: FrameTransport, Body: []byte{1, 2, 3}}
	got, err := ParseFrame(MarshalFrame(f))
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if got.Kind != f.Kind || !bytes.Equal(got.Body, f.Body) {
		t.Errorf("round-trip mismatch")
	}
}

func TestParseFrame_Empty(t *testing.T) {
	if _, err := ParseFrame(nil); err == nil {
		t.Error("expected error on empty")
	}
}

func TestAttestationFrame_RoundTrip(t *testing.T) {
	wire := MarshalAttestation([]byte("ev"), []byte("end"))
	ev, end, err := ParseAttestation(wire)
	if err != nil {
		t.Fatalf("ParseAttestation: %v", err)
	}
	if string(ev) != "ev" || string(end) != "end" {
		t.Errorf("round-trip mismatch")
	}
}

func TestParseAttestation_BadInputs(t *testing.T) {
	if _, _, err := ParseAttestation(make([]byte, 2)); err == nil {
		t.Error("too-short must error")
	}
	if _, _, err := ParseAttestation([]byte{0, 0, 0, 0xff, 0, 0, 0, 0}); err == nil {
		t.Error("overflow must error")
	}
}

func TestNewSession_Validation(t *testing.T) {
	priv, pub := newServerKeys(t)
	d := NewDispatcher(NewMemoryDirectory())
	if _, err := NewSession(SessionConfig{}); err == nil {
		t.Error("expected error on missing dispatcher")
	}
	if _, err := NewSession(SessionConfig{
		Dispatcher: d, StaticPrivateKey: make([]byte, 31), StaticPublicKey: pub, Identity: "x",
	}); err == nil {
		t.Error("expected error on short priv")
	}
	if _, err := NewSession(SessionConfig{
		Dispatcher: d, StaticPrivateKey: priv, StaticPublicKey: pub,
	}); err == nil {
		t.Error("expected error on missing identity")
	}
}

func TestSession_FullHandshakeAndLookup(t *testing.T) {
	priv, pub := newServerKeys(t)
	dir := NewMemoryDirectory()
	var aci, pni [16]byte
	aci[0] = 1
	pni[1] = 2
	dir.Upsert(Entry{E164: 15551112222, ACI: aci, PNI: pni})
	d := NewDispatcher(dir)
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
	// Attestation frame.
	att := sess.AttestationFrame()
	if att.Kind != FrameAttestation {
		t.Errorf("att kind = %d", att.Kind)
	}
	// Build client-side handshake.
	uv, err := attest.NewNKhfsInitiator(pub)
	if err != nil {
		t.Fatalf("NewNKhfsInitiator: %v", err)
	}
	cli := uv.SkipRaftValidation()
	msg2, err := sess.HandleHandshake(Frame{Kind: FrameHandshake1, Body: cli.InitialRequest()})
	if err != nil {
		t.Fatalf("HandleHandshake: %v", err)
	}
	if msg2.Kind != FrameHandshake2 {
		t.Errorf("msg2 kind = %d", msg2.Kind)
	}
	conn, err := cli.Complete(msg2.Body)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if !bytes.Equal(conn.HandshakeHash, sess.HandshakeHash()) {
		t.Error("handshake hash mismatch")
	}
	// Encrypted lookup.
	req := &cdsipb.ClientRequest{E164SBytes: packE164s(15551112222)}
	frame, _ := proto.Marshal(req)
	ct, _ := conn.Send(frame)
	resp, err := sess.HandleTransport(context.Background(), Frame{Kind: FrameTransport, Body: ct})
	if err != nil {
		t.Fatalf("HandleTransport: %v", err)
	}
	plain, err := conn.Recv(resp.Body)
	if err != nil {
		t.Fatalf("conn.Recv: %v", err)
	}
	var rp cdsipb.ClientResponse
	if err := proto.Unmarshal(plain, &rp); err != nil {
		t.Fatalf("unmarshal resp: %v", err)
	}
	if len(rp.E164PniAciTriples) != responseEntryLen {
		t.Fatalf("triples len = %d", len(rp.E164PniAciTriples))
	}
	// PNI returned, ACI absent (no access key supplied).
	if !bytes.Equal(rp.E164PniAciTriples[8:24], pni[:]) {
		t.Error("PNI mismatch")
	}
	var zero [16]byte
	if !bytes.Equal(rp.E164PniAciTriples[24:40], zero[:]) {
		t.Error("ACI must be zero without access-key proof")
	}
	// E.164 echoed.
	if binary.BigEndian.Uint64(rp.E164PniAciTriples[:8]) != 15551112222 {
		t.Error("E.164 echo mismatch")
	}
}

func TestSession_TransportBeforeHandshakeRejected(t *testing.T) {
	priv, pub := newServerKeys(t)
	d := NewDispatcher(NewMemoryDirectory())
	sess, _ := NewSession(SessionConfig{
		Identity: "alice", StaticPrivateKey: priv, StaticPublicKey: pub, Dispatcher: d,
	})
	_, err := sess.HandleTransport(context.Background(), Frame{Kind: FrameTransport, Body: []byte("x")})
	if err == nil {
		t.Error("expected error on transport before handshake")
	}
}

func TestHandleHandshake_AlreadyDone(t *testing.T) {
	priv, pub := newServerKeys(t)
	d := NewDispatcher(NewMemoryDirectory())
	sess, _ := NewSession(SessionConfig{
		Identity:         "bob",
		StaticPrivateKey: priv,
		StaticPublicKey:  pub,
		Dispatcher:       d,
	})
	uv, _ := attest.NewNKhfsInitiator(pub)
	hs := uv.SkipRaftValidation()
	msg1 := Frame{Kind: FrameHandshake1, Body: hs.InitialRequest()}
	if _, err := sess.HandleHandshake(msg1); err != nil {
		t.Fatalf("first HandleHandshake: %v", err)
	}
	// Second attempt must fail.
	if _, err := sess.HandleHandshake(msg1); err == nil {
		t.Error("expected error on second HandleHandshake")
	}
}

func TestHandleTransport_WrongFrameKind(t *testing.T) {
	priv, pub := newServerKeys(t)
	d := NewDispatcher(NewMemoryDirectory())
	sess, _ := NewSession(SessionConfig{
		Identity:         "carol",
		StaticPrivateKey: priv,
		StaticPublicKey:  pub,
		Dispatcher:       d,
	})
	uv, _ := attest.NewNKhfsInitiator(pub)
	hs := uv.SkipRaftValidation()
	msg2, err := sess.HandleHandshake(Frame{Kind: FrameHandshake1, Body: hs.InitialRequest()})
	if err != nil {
		t.Fatalf("HandleHandshake: %v", err)
	}
	if _, err := hs.Complete(msg2.Body); err != nil {
		t.Fatalf("client Complete: %v", err)
	}
	// Non-transport frame after handshake.
	_, err = sess.HandleTransport(context.Background(), Frame{Kind: FrameHandshake1, Body: []byte{1}})
	if err == nil {
		t.Error("expected error for wrong frame kind in HandleTransport")
	}
}

func TestParseAttestation_TrailingBytes(t *testing.T) {
	wire := MarshalAttestation([]byte("ev"), []byte("end"))
	wire = append(wire, 0xFF) // trailing garbage
	if _, _, err := ParseAttestation(wire); err == nil {
		t.Error("expected error for trailing bytes in attestation buffer")
	}
}

func TestReadUint32BE_ShortBuffer(t *testing.T) {
	r := bytes.NewReader([]byte{1, 2})
	if _, err := readUint32BE(r); err == nil {
		t.Error("expected error from readUint32BE on short buffer")
	}
}
