package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// SoftwareAttester signs (server_static_pub || boundData) with a
// deployment-time ed25519 signing key. Clients validate the signature
// against an operator-pinned ed25519 public key.
//
// The Evidence envelope:
//
//	evidence    = staticPub(32) ‖ boundDataLen(4 BE) ‖ boundData ‖ ed25519Sig(64)
//	endorsement = signerPub(32)  // operator's ed25519 public key
//
// The signer's public key is the deployment trust anchor. In
// production the operator distributes signerPub via the same channel
// the client uses to pin SVR endpoints (Signal-Server config, app
// bundle). Rotating the deployment trust anchor means re-publishing
// the pin.
type SoftwareAttester struct {
	signerPriv ed25519.PrivateKey
	signerPub  ed25519.PublicKey
	staticPriv []byte
	staticPub  []byte
}

// SoftwareConfig configures a SoftwareAttester.
type SoftwareConfig struct {
	// SignerPrivateKey is the operator's ed25519 signing key
	// (PKCS#8 DER seed is fine; ed25519.PrivateKey is 64 bytes). If
	// nil, NewSoftware generates a fresh one — only do that in tests.
	SignerPrivateKey ed25519.PrivateKey

	// StaticPrivateKey is the server's static Noise X25519 private
	// scalar (32 bytes). If nil, NewSoftware generates a fresh pair
	// — most production deployments want a persistent pair so
	// existing pinned-public-key clients keep working across restarts.
	StaticPrivateKey []byte
}

// NewSoftware constructs a SoftwareAttester. Any unset field in cfg is
// generated fresh; production deployments supply both so the static
// Noise public key stays stable across restarts.
func NewSoftware(cfg SoftwareConfig) (*SoftwareAttester, error) {
	signerPriv := cfg.SignerPrivateKey
	if signerPriv == nil {
		_, sk, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		signerPriv = sk
	}
	if len(signerPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("attestation: ed25519 private key must be 64 bytes")
	}

	staticPriv := cfg.StaticPrivateKey
	if staticPriv == nil {
		staticPriv = make([]byte, 32)
		if _, err := rand.Read(staticPriv); err != nil {
			return nil, err
		}
	}
	if len(staticPriv) != 32 {
		return nil, errors.New("attestation: static private key must be 32 bytes")
	}
	staticPub, err := curve25519.X25519(staticPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	signerPub, ok := signerPriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("attestation: ed25519 private key did not yield an ed25519 public key")
	}

	return &SoftwareAttester{
		signerPriv: signerPriv,
		signerPub:  signerPub,
		staticPriv: append([]byte(nil), staticPriv...),
		staticPub:  staticPub,
	}, nil
}

// Attest produces fresh evidence binding boundData. The envelope is
// deterministic given the inputs because ed25519 signing is
// deterministic; this is intentional so two attesters running side-by-
// side with the same key material produce identical bytes (useful for
// HA deployments behind a load balancer where any replica's evidence
// is acceptable to clients).
func (s *SoftwareAttester) Attest(_ context.Context, boundData []byte) (*Evidence, error) {
	// Compose the signed payload: staticPub || sha256(boundData).
	// We hash boundData so the signed message stays fixed-length
	// regardless of the bound payload's size.
	bdHash := sha256.Sum256(boundData)
	signed := make([]byte, 0, 32+32)
	signed = append(signed, s.staticPub...)
	signed = append(signed, bdHash[:]...)
	sig := ed25519.Sign(s.signerPriv, signed)

	// Wire envelope: staticPub(32) || boundDataLen(4 BE) || boundData || sig(64).
	if len(boundData) > 1<<24 {
		return nil, errors.New("attestation: boundData too large")
	}
	out := make([]byte, 0, 32+4+len(boundData)+ed25519.SignatureSize)
	out = append(out, s.staticPub...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(boundData)))
	out = append(out, boundData...)
	out = append(out, sig...)

	return &Evidence{
		Evidence:    out,
		Endorsement: append([]byte(nil), s.signerPub...),
	}, nil
}

// PublicKey returns the server's static Noise X25519 public key.
func (s *SoftwareAttester) PublicKey() []byte {
	return append([]byte(nil), s.staticPub...)
}

// StaticPrivateKey returns a defensive copy of the X25519 static
// private key. cmd/svr2's NKhfs responder needs the private key; this
// method is the only path to it.
func (s *SoftwareAttester) StaticPrivateKey() []byte {
	return append([]byte(nil), s.staticPriv...)
}

// SignerPublic returns the operator's ed25519 public key. Tests and
// the client-side validator use this; production clients pin a known
// value from operator config.
func (s *SoftwareAttester) SignerPublic() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.signerPub...)
}

// Type returns "software".
func (s *SoftwareAttester) Type() string { return "software" }

// VerifySoftwareEvidence validates a software-attestation envelope
// against a trusted signer public key. Returns the attested static
// public key and the boundData on success.
//
// This is the client-side validator. Tests and (eventually) the
// mobile-client-side go-libsignal port consume it. Implementations of
// the SVR2 Noise client elsewhere translate this into the
// "evidence + endorsement" parse path.
func VerifySoftwareEvidence(envelope, expectedSignerPub []byte) (staticPub, boundData []byte, err error) {
	if len(envelope) < 32+4+ed25519.SignatureSize {
		return nil, nil, errors.New("attestation: envelope too short")
	}
	staticPub = envelope[:32]
	bdLen := binary.BigEndian.Uint32(envelope[32:36])
	if uint64(36+bdLen+ed25519.SignatureSize) != uint64(len(envelope)) {
		return nil, nil, errors.New("attestation: envelope length mismatch")
	}
	boundData = envelope[36 : 36+bdLen]
	sig := envelope[36+bdLen:]

	if len(expectedSignerPub) != ed25519.PublicKeySize {
		return nil, nil, errors.New("attestation: signer pub wrong size")
	}
	bdHash := sha256.Sum256(boundData)
	signed := make([]byte, 0, 64)
	signed = append(signed, staticPub...)
	signed = append(signed, bdHash[:]...)
	if !ed25519.Verify(ed25519.PublicKey(expectedSignerPub), signed, sig) {
		return nil, nil, errors.New("attestation: signature verification failed")
	}
	return staticPub, boundData, nil
}
