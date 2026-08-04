package cdsi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"
)

// SessionConfig configures a Session. Mirrors svr2's session config —
// the Noise + framing pattern is identical; only the post-handshake
// dispatch differs.
type SessionConfig struct {
	Identity         string
	StaticPrivateKey []byte
	StaticPublicKey  []byte
	Evidence         []byte
	Endorsement      []byte
	Dispatcher       *Dispatcher
}

// Session is a single CDSI conversation over a duplex byte stream.
type Session struct {
	cfg    SessionConfig
	sendCS *attest.NKhfsCipherState
	recvCS *attest.NKhfsCipherState
	hsHash []byte
	done   bool
}

// NewSession constructs a Session. Validates required wiring fields.
func NewSession(cfg SessionConfig) (*Session, error) {
	if cfg.Dispatcher == nil {
		return nil, errors.New("cdsi: Dispatcher is required")
	}
	if len(cfg.StaticPrivateKey) != 32 || len(cfg.StaticPublicKey) != 32 {
		return nil, errors.New("cdsi: static key pair must be 32 bytes each")
	}
	if cfg.Identity == "" {
		return nil, errors.New("cdsi: Identity is required")
	}
	return &Session{cfg: cfg}, nil
}

// FrameKind identifies the role of a wire frame.
type FrameKind uint8

const (
	FrameAttestation FrameKind = 1
	FrameHandshake1  FrameKind = 2
	FrameHandshake2  FrameKind = 3
	FrameTransport   FrameKind = 4
)

// Frame is the wire envelope: 1-byte kind followed by the body.
type Frame struct {
	Kind FrameKind
	Body []byte
}

// MarshalFrame encodes a Frame for the wire.
func MarshalFrame(f Frame) []byte {
	out := make([]byte, 1+len(f.Body))
	out[0] = byte(f.Kind)
	copy(out[1:], f.Body)
	return out
}

// ParseFrame decodes a wire frame.
func ParseFrame(b []byte) (Frame, error) {
	if len(b) < 1 {
		return Frame{}, errors.New("cdsi: frame too short")
	}
	return Frame{Kind: FrameKind(b[0]), Body: b[1:]}, nil
}

// MarshalAttestation packs (evidence, endorsement) for the
// attestation frame. Same shape as svr2's MarshalAttestation.
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
		return nil, nil, errors.New("cdsi: attestation buffer too short")
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
		return nil, nil, errors.New("cdsi: trailing bytes in attestation buffer")
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

// AttestationFrame returns the first server-to-client frame.
func (s *Session) AttestationFrame() Frame {
	return Frame{Kind: FrameAttestation, Body: MarshalAttestation(s.cfg.Evidence, s.cfg.Endorsement)}
}

// HandleHandshake processes the client's NKhfs message 1 and returns
// the server's message 2. After it completes, the session is ready
// for transport frames.
func (s *Session) HandleHandshake(msg1 Frame) (Frame, error) {
	if s.done {
		return Frame{}, errors.New("cdsi: handshake already complete")
	}
	if msg1.Kind != FrameHandshake1 {
		return Frame{}, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("cdsi: expected FrameHandshake1, got %d", msg1.Kind))
	}
	r, err := attest.NewNKhfsResponder(s.cfg.StaticPrivateKey, s.cfg.StaticPublicKey)
	if err != nil {
		return Frame{}, err
	}
	msg2, sendCS, recvCS, hsHash, err := r.ProcessMessage1(msg1.Body)
	if err != nil {
		return Frame{}, err
	}
	s.sendCS = sendCS
	s.recvCS = recvCS
	s.hsHash = hsHash
	s.done = true
	return Frame{Kind: FrameHandshake2, Body: msg2}, nil
}

// HandleTransport decrypts an inbound transport frame, runs the
// dispatcher, and encrypts the response.
func (s *Session) HandleTransport(ctx context.Context, in Frame) (Frame, error) {
	if !s.done {
		return Frame{}, errors.New("cdsi: transport frame before handshake")
	}
	if in.Kind != FrameTransport {
		return Frame{}, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("cdsi: expected FrameTransport, got %d", in.Kind))
	}
	plain, err := s.recvCS.Decrypt(nil, in.Body)
	if err != nil {
		return Frame{}, err
	}
	resp, err := s.cfg.Dispatcher.Handle(ctx, plain)
	if err != nil {
		return Frame{}, err
	}
	ct, err := s.sendCS.Encrypt(nil, resp)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Kind: FrameTransport, Body: ct}, nil
}

// HandshakeHash returns the binding hash post-handshake (nil before).
func (s *Session) HandshakeHash() []byte {
	return append([]byte(nil), s.hsHash...)
}
