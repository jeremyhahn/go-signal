package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strconv"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"golang.org/x/crypto/curve25519"
)

// TPM is the narrow surface go-signal consumes from a higher-level
// application's TPM 2.0 implementation. Its method signatures match
// `github.com/jeremyhahn/go-xkms/pkg/tpm2.TrustedPlatformModule`
// exactly so a higher-level binary (go-quicbaas, go-trusted-platform,
// etc.) can pass its TrustedPlatformModule straight to
// NewTPMAttester via Go's structural-typing rules — go-signal stays
// free of any native TPM binding and pulls zero TPM transport
// dependencies.
//
// The shipped Attester wraps this interface; it never opens a TPM
// device or speaks the TPM 2.0 wire protocol. Production deployments
// inject the implementation; tests inject a stub.
type TPM interface {
	// RandomBytes returns fixedLength bytes of TPM-backed entropy.
	// Wire-compatible with go-xkms TrustedPlatformModule.RandomBytes.
	RandomBytes(fixedLength int) ([]byte, error)

	// EKCertificate returns the Endorsement Key certificate. Used by
	// the client-side verifier to anchor the attestation chain at
	// the manufacturer's pre-installed cert. Wire-compatible with
	// go-xkms TrustedPlatformModule.EKCertificate.
	EKCertificate() (*x509.Certificate, error)
}

// TPMAttester anchors attestation in an injected TPM implementation.
// The struct holds only the bound static Noise key + the TPM
// reference; every TPM 2.0 wire interaction happens through the
// supplied TPM interface.
//
// Trust model:
//
//   - The TPM holds key material; we never touch raw TPM commands.
//   - The EK certificate (vendor-burned at manufacturing time) is
//     the external trust anchor. Higher-level applications surface
//     their AIK certification + Quote chain on top of this
//     adapter as they extend the wire format.
//
// This is the future-proof confidential-computing baseline: Intel
// TDX and AMD SEV-SNP both layer measurement attestation on top of
// (or alongside) TPM quotes. Future TDXAttester / SEVAttester impls
// drop in alongside TPMAttester without touching the Attester
// interface.
type TPMAttester struct {
	tpm        TPM
	staticPriv []byte
	staticPub  []byte
}

// TPMConfig configures a TPMAttester.
type TPMConfig struct {
	// TPM is the injected implementation. Required — go-signal
	// holds no native TPM transport. Production deployments pass
	// their go-xkms TrustedPlatformModule directly; tests pass a
	// stub that satisfies the narrow TPM interface above.
	TPM TPM

	// StaticPrivateKey is the server's static Noise X25519 private
	// scalar (32 bytes). When nil a fresh pair is generated via
	// TPM.RandomBytes — production deployments supply a persistent
	// pair so existing pinned-public-key clients keep working
	// across restarts.
	StaticPrivateKey []byte
}

// NewTPM constructs a TPMAttester. Returns an error when the TPM
// implementation is missing or the supplied key material is
// malformed. The TPM is never opened or probed here — the higher
// layer is expected to have done that already.
func NewTPM(cfg TPMConfig) (*TPMAttester, error) {
	if cfg.TPM == nil {
		return nil, &AttestUnavailableError{Detail: "TPM implementation must be injected"}
	}

	staticPriv := cfg.StaticPrivateKey
	if staticPriv == nil {
		fresh, err := cfg.TPM.RandomBytes(32)
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "tpm random", err)
		}
		if len(fresh) != 32 {
			return nil, signalerrors.New(signalerrors.ErrInternal, "tpm random returned "+strconv.Itoa(len(fresh))+" bytes, want 32")
		}
		staticPriv = fresh
	}
	if len(staticPriv) != 32 {
		return nil, errors.New("attestation: static private key must be 32 bytes")
	}
	staticPub, err := curve25519.X25519(staticPriv, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return &TPMAttester{
		tpm:        cfg.TPM,
		staticPriv: append([]byte(nil), staticPriv...),
		staticPub:  staticPub,
	}, nil
}

// Attest produces an attestation envelope that commits to boundData
// under the TPM's entropy source.
//
// Wire format (v1 baseline):
//
//	evidence    = "TPM1" magic(4) || staticPub(32) || sha256(boundData)(32) || tpmRandom(32)
//	endorsement = DER(EKCertificate)
//
// Higher-level applications layering full TPM2_Quote / AIK signing
// over this adapter extend the envelope additively — clients
// dispatch on the magic prefix to support multiple revisions.
func (a *TPMAttester) Attest(_ context.Context, boundData []byte) (*Evidence, error) {
	bdHash := sha256.Sum256(boundData)
	random, err := a.tpm.RandomBytes(32)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "attestation: tpm RandomBytes", err)
	}
	if len(random) != 32 {
		return nil, signalerrors.New(signalerrors.ErrInternal, "attestation: tpm returned "+strconv.Itoa(len(random))+" random bytes, want 32")
	}

	envelope := make([]byte, 0, 4+32+32+32)
	envelope = append(envelope, 'T', 'P', 'M', '1')
	envelope = append(envelope, a.staticPub...)
	envelope = append(envelope, bdHash[:]...)
	envelope = append(envelope, random...)

	// Endorsement: the manufacturer-burned EK certificate. Clients
	// validate this chain against their pinned vendor root pool.
	// Some test TPMs don't ship an EK cert — surface that as an
	// empty Endorsement rather than a failure so dev / CI rigs
	// without one keep working.
	var endorsement []byte
	if ekCert, certErr := a.tpm.EKCertificate(); certErr == nil && ekCert != nil {
		endorsement = ekCert.Raw
	}

	return &Evidence{
		Evidence:    envelope,
		Endorsement: endorsement,
	}, nil
}

// PublicKey returns the server's static Noise X25519 public key.
func (a *TPMAttester) PublicKey() []byte {
	return append([]byte(nil), a.staticPub...)
}

// StaticPrivateKey returns a defensive copy of the static private
// key. cmd/svr2 and cmd/cdsi's Noise responder need the private key;
// this method is the only path to it.
func (a *TPMAttester) StaticPrivateKey() []byte {
	return append([]byte(nil), a.staticPriv...)
}

// Type returns "tpm".
func (a *TPMAttester) Type() string { return "tpm" }

// Close scrubs the static X25519 private key from the attester's
// memory and detaches the injected TPM reference. The TPM itself is
// not closed — go-signal does not own its lifecycle; the
// higher-level application that constructed the TPM is responsible
// for closing it.
//
// Close is idempotent. Callers that need the static private key
// (e.g. cmd/svr2's Noise responder) must obtain it via
// StaticPrivateKey BEFORE calling Close — subsequent reads return
// an empty slice.
func (a *TPMAttester) Close() error {
	if a == nil {
		return nil
	}
	for i := range a.staticPriv {
		a.staticPriv[i] = 0
	}
	a.staticPriv = nil
	a.tpm = nil
	return nil
}
