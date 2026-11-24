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

// TPM is the subset of go-xkms tpm2.TrustedPlatformModule go-signal needs; callers inject an implementation and go-signal opens no TPM itself.
type TPM interface {
	// RandomBytes returns fixedLength bytes of TPM-backed entropy.
	// Wire-compatible with go-xkms TrustedPlatformModule.RandomBytes.
	RandomBytes(fixedLength int) ([]byte, error)

	// EKCertificate returns the Endorsement Key certificate that anchors the attestation chain.
	EKCertificate() (*x509.Certificate, error)
}

// TPMAttester anchors attestation in an injected TPM, with the EK certificate as trust anchor; it holds only the static Noise key and the TPM.
type TPMAttester struct {
	tpm        TPM
	staticPriv []byte
	staticPub  []byte
}

// TPMConfig configures a TPMAttester.
type TPMConfig struct {
	// TPM is the required injected implementation.
	TPM TPM

	// StaticPrivateKey is the 32-byte static Noise X25519 key; nil generates one via TPM.RandomBytes. Supply a persistent key for pinned clients.
	StaticPrivateKey []byte
}

// NewTPM returns a TPMAttester, or an error when the TPM is missing or the key is malformed; it does not probe the TPM.
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

// Attest commits to boundData: evidence = "TPM1" || staticPub(32) || sha256(boundData)(32) || tpmRandom(32), endorsement = DER(EKCertificate).
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

	// Endorsement is the EK certificate; a TPM without one yields an empty Endorsement.
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

// Close wipes the static key and drops the TPM reference without closing it; idempotent. Read StaticPrivateKey before Close.
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
