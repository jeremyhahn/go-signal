package svr2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"
)

// SessionConfig configures a Session.
type SessionConfig struct {
	// Identity is the authenticated principal — the HMAC username
	// extracted from the chat-server-issued credential by the
	// HTTP-layer auth check.
	Identity string

	// StaticPrivateKey is the server's static X25519 private scalar.
	// Pair with the attester's PublicKey.
	StaticPrivateKey []byte

	// StaticPublicKey is the matching public key. The first message
	// the server sends contains this (wrapped in attestation
	// evidence) so the client can mix it into the handshake hash.
	StaticPublicKey []byte

	// Evidence is the attestation envelope sent as the first server
	// message on a new WebSocket. It commits to StaticPublicKey.
	Evidence []byte

	// Endorsement is the trust-chain envelope sent alongside
	// Evidence. Software attestation puts the operator's ed25519
	// public key here; TPM puts the EK certificate chain.
	Endorsement []byte

	// Dispatcher routes decrypted Request4 frames onto Storage ops.
	Dispatcher *Dispatcher
}

// Session is a single Noise-attested SVR4 conversation over a duplex
// byte stream (typically a WebSocket). The Session owns the post-
// handshake cipher states and serialises read/write through them.
type Session struct {
	cfg     SessionConfig
	sendCS  *attest.NKhfsCipherState
	recvCS  *attest.NKhfsCipherState
	hsHash  []byte
	done    bool
	stalled bool
}

// NewSession constructs a Session. Validates required fields; panics
// only on programmer errors (nil Dispatcher).
func NewSession(cfg SessionConfig) (*Session, error) {
	if cfg.Dispatcher == nil {
		return nil, errors.New("svr2: Dispatcher is required")
	}
	if len(cfg.StaticPrivateKey) != 32 || len(cfg.StaticPublicKey) != 32 {
		return nil, errors.New("svr2: static key pair must be 32 bytes each")
	}
	if cfg.Identity == "" {
		return nil, errors.New("svr2: Identity is required")
	}
	return &Session{cfg: cfg}, nil
}

// Frame is a length-prefixed wire envelope. Each WebSocket binary
// message carries exactly one Frame.
type Frame struct {
	Kind FrameKind
	Body []byte
}

// FrameKind identifies the role of a wire frame.
type FrameKind uint8

const (
	// FrameAttestation is the first server-to-client frame, carrying
	// (evidence || endorsement) prefixed by their lengths.
	FrameAttestation FrameKind = 1
	// FrameHandshake1 is the client's Noise NKhfs message 1 (-> e, es, e1).
	FrameHandshake1 FrameKind = 2
	// FrameHandshake2 is the server's Noise NKhfs message 2 (<- e, ee, ekem1).
	FrameHandshake2 FrameKind = 3
	// FrameTransport carries an encrypted Request4 or Response4 payload.
	FrameTransport FrameKind = 4
)

// MarshalFrame encodes a Frame for the wire: 1-byte kind + body.
func MarshalFrame(f Frame) []byte {
	out := make([]byte, 1+len(f.Body))
	out[0] = byte(f.Kind)
	copy(out[1:], f.Body)
	return out
}

// ParseFrame decodes a wire frame produced by MarshalFrame.
func ParseFrame(b []byte) (Frame, error) {
	if len(b) < 1 {
		return Frame{}, errors.New("svr2: frame too short")
	}
	return Frame{Kind: FrameKind(b[0]), Body: b[1:]}, nil
}

// MarshalAttestation packs evidence + endorsement into a single
// length-prefixed buffer suitable for FrameAttestation.Body.
//
// Wire shape: evLen(4 BE) || ev || endLen(4 BE) || end.
func MarshalAttestation(evidence, endorsement []byte) []byte {
	out := make([]byte, 0, 4+len(evidence)+4+len(endorsement))
	out = appendUint32BE(out, uint32(len(evidence)))
	out = append(out, evidence...)
	out = appendUint32BE(out, uint32(len(endorsement)))
	out = append(out, endorsement...)
	return out
}

// ParseAttestation decodes the buffer produced by MarshalAttestation.
func ParseAttestation(b []byte) (evidence, endorsement []byte, err error) {
	if len(b) < 8 {
		return nil, nil, errors.New("svr2: attestation buffer too short")
	}
	r := bytes.NewReader(b)
	evLen, err := readUint32BE(r)
	if err != nil {
		return nil, nil, err
	}
	ev := make([]byte, evLen)
	if _, err := io.ReadFull(r, ev); err != nil {
		return nil, nil, err
	}
	endLen, err := readUint32BE(r)
	if err != nil {
		return nil, nil, err
	}
	end := make([]byte, endLen)
	if _, err := io.ReadFull(r, end); err != nil {
		return nil, nil, err
	}
	if r.Len() != 0 {
		return nil, nil, errors.New("svr2: attestation buffer has trailing bytes")
	}
	return ev, end, nil
}

func appendUint32BE(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func readUint32BE(r io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return uint32(buf[0])<<24 | uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3]), nil
}

// AttestationFrame returns the first server-to-client wire frame.
func (s *Session) AttestationFrame() Frame {
	return Frame{
		Kind: FrameAttestation,
		Body: MarshalAttestation(s.cfg.Evidence, s.cfg.Endorsement),
	}
}

// HandleHandshake processes the client's message-1 frame, runs the
// NKhfs responder, and returns the message-2 frame. After it
// completes, the session is ready for transport frames.
func (s *Session) HandleHandshake(msg1 Frame) (Frame, error) {
	if s.done {
		return Frame{}, errors.New("svr2: handshake already complete")
	}
	if msg1.Kind != FrameHandshake1 {
		return Frame{}, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("svr2: expected FrameHandshake1, got %d", msg1.Kind))
	}
	responder, err := attest.NewNKhfsResponder(s.cfg.StaticPrivateKey, s.cfg.StaticPublicKey)
	if err != nil {
		return Frame{}, err
	}
	msg2, sendCS, recvCS, hsHash, err := responder.ProcessMessage1(msg1.Body)
	if err != nil {
		s.stalled = true
		return Frame{}, err
	}
	s.sendCS = sendCS
	s.recvCS = recvCS
	s.hsHash = hsHash
	s.done = true
	return Frame{Kind: FrameHandshake2, Body: msg2}, nil
}

// HandleTransport decrypts the inbound transport frame, dispatches
// the contained Request4 against the storage backend, and returns
// the encrypted Response4 frame.
func (s *Session) HandleTransport(ctx context.Context, in Frame) (Frame, error) {
	if !s.done {
		return Frame{}, errors.New("svr2: transport frame before handshake complete")
	}
	if in.Kind != FrameTransport {
		return Frame{}, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("svr2: expected FrameTransport, got %d", in.Kind))
	}
	plaintext, err := s.recvCS.Decrypt(nil, in.Body)
	if err != nil {
		return Frame{}, err
	}
	respBytes, err := s.cfg.Dispatcher.Handle(ctx, s.cfg.Identity, plaintext)
	if err != nil {
		return Frame{}, err
	}
	ct, err := s.sendCS.Encrypt(nil, respBytes)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Kind: FrameTransport, Body: ct}, nil
}

// HandshakeHash returns the binding hash post-handshake (nil before).
func (s *Session) HandshakeHash() []byte {
	return append([]byte(nil), s.hsHash...)
}
