package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
)

// fakeTPM satisfies the narrow TPM interface for unit tests.
// Production code injects go-xkms TrustedPlatformModule instances
// which expose the same RandomBytes + EKCertificate signatures.
type fakeTPM struct {
	random  []byte
	randErr error
	cert    *x509.Certificate
	certErr error
}

func (f *fakeTPM) RandomBytes(fixedLength int) ([]byte, error) {
	if f.randErr != nil {
		return nil, f.randErr
	}
	if f.random == nil {
		// Deterministic non-zero default so the Curve25519 derivation
		// path runs cleanly.
		out := make([]byte, fixedLength)
		for i := range out {
			out[i] = byte(i + 1)
		}
		return out, nil
	}
	if len(f.random) >= fixedLength {
		return f.random[:fixedLength], nil
	}
	return f.random, nil
}

func (f *fakeTPM) EKCertificate() (*x509.Certificate, error) {
	if f.certErr != nil {
		return nil, f.certErr
	}
	return f.cert, nil
}

func TestNewTPM_RequiresInjectedTPM(t *testing.T) {
	_, err := NewTPM(TPMConfig{})
	if err == nil {
		t.Fatal("expected error when TPM is nil")
	}
	if !errors.Is(err, ErrAttestUnavailable) {
		t.Errorf("expected ErrAttestUnavailable, got %v", err)
	}
}

func TestNewTPM_AcceptsSuppliedStaticKey(t *testing.T) {
	priv := make([]byte, 32)
	priv[31] = 0x42
	a, err := NewTPM(TPMConfig{TPM: &fakeTPM{}, StaticPrivateKey: priv})
	if err != nil {
		t.Fatalf("NewTPM: %v", err)
	}
	if got := a.StaticPrivateKey(); got[31] != 0x42 {
		t.Errorf("static priv not preserved: %v", got[31])
	}
}

func TestNewTPM_MintsKeyViaTPMWhenAbsent(t *testing.T) {
	tpm := &fakeTPM{}
	a, err := NewTPM(TPMConfig{TPM: tpm})
	if err != nil {
		t.Fatalf("NewTPM: %v", err)
	}
	if len(a.StaticPrivateKey()) != 32 || len(a.PublicKey()) != 32 {
		t.Error("static key pair must be 32 bytes each")
	}
}

func TestNewTPM_RejectsBadStaticKeyLength(t *testing.T) {
	_, err := NewTPM(TPMConfig{TPM: &fakeTPM{}, StaticPrivateKey: make([]byte, 31)})
	if err == nil {
		t.Error("expected error on short static priv")
	}
}

func TestNewTPM_PropagatesRandFailure(t *testing.T) {
	want := errors.New("tpm wedged")
	_, err := NewTPM(TPMConfig{TPM: &fakeTPM{randErr: want}})
	if !errors.Is(err, want) {
		t.Errorf("expected wrap of want; got %v", err)
	}
}

func TestTPMAttester_AttestEnvelopeShape(t *testing.T) {
	tpm := &fakeTPM{random: append([]byte("TPM1"), make([]byte, 60)...)}
	// Use TPM-supplied random for key derivation, then a different
	// fixed payload for the attestation random.
	a, err := NewTPM(TPMConfig{TPM: tpm, StaticPrivateKey: make([]byte, 32)})
	if err != nil {
		t.Fatalf("NewTPM: %v", err)
	}
	// Override the fake's random for the Attest call's RandomBytes.
	tpm.random = make([]byte, 32)
	for i := range tpm.random {
		tpm.random[i] = 0xAB
	}

	ev, err := a.Attest(context.Background(), []byte("payload"))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	envelope := ev.Evidence
	// Expected: 4 (magic) + 32 (staticPub) + 32 (sha256) + 32 (random) = 100.
	if len(envelope) != 100 {
		t.Fatalf("envelope len = %d, want 100", len(envelope))
	}
	if string(envelope[:4]) != "TPM1" {
		t.Errorf("magic = %q", envelope[:4])
	}
	bdHash := sha256.Sum256([]byte("payload"))
	if string(envelope[36:68]) != string(bdHash[:]) {
		t.Errorf("boundData hash mismatch")
	}
	for i := 68; i < 100; i++ {
		if envelope[i] != 0xAB {
			t.Errorf("random byte %d = %#x, want 0xab", i, envelope[i])
			break
		}
	}
}

func TestTPMAttester_PropagatesRandFailureAtAttest(t *testing.T) {
	tpm := &fakeTPM{}
	a, _ := NewTPM(TPMConfig{TPM: tpm, StaticPrivateKey: make([]byte, 32)})
	tpm.randErr = errors.New("post-init tpm failure")
	if _, err := a.Attest(context.Background(), []byte("x")); err == nil {
		t.Error("expected error when TPM random fails during Attest")
	}
}

func TestTPMAttester_NoEKCertIsAcceptable(t *testing.T) {
	tpm := &fakeTPM{cert: nil}
	a, _ := NewTPM(TPMConfig{TPM: tpm, StaticPrivateKey: make([]byte, 32)})
	ev, err := a.Attest(context.Background(), []byte("x"))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if len(ev.Endorsement) != 0 {
		t.Errorf("Endorsement should be empty when no EK cert; got %d bytes", len(ev.Endorsement))
	}
}

func TestTPMAttester_PopulatesEKCertWhenPresent(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("fake-ek-cert-der")}
	tpm := &fakeTPM{cert: cert}
	a, _ := NewTPM(TPMConfig{TPM: tpm, StaticPrivateKey: make([]byte, 32)})
	ev, _ := a.Attest(context.Background(), []byte("x"))
	if string(ev.Endorsement) != "fake-ek-cert-der" {
		t.Errorf("Endorsement = %q", ev.Endorsement)
	}
}

func TestTPMAttester_TypeAndCloseAreContractStable(t *testing.T) {
	a, _ := NewTPM(TPMConfig{TPM: &fakeTPM{}, StaticPrivateKey: make([]byte, 32)})
	if a.Type() != "tpm" {
		t.Errorf("Type = %q", a.Type())
	}
	if err := a.Close(); err != nil {
		t.Errorf("Close returned %v, want nil", err)
	}
}

func TestTPMAttester_CloseScrubsStaticPrivateKey(t *testing.T) {
	nonZero := make([]byte, 32)
	for i := range nonZero {
		nonZero[i] = 0xAA
	}
	a, err := NewTPM(TPMConfig{TPM: &fakeTPM{}, StaticPrivateKey: nonZero})
	if err != nil {
		t.Fatalf("NewTPM: %v", err)
	}

	// Snapshot before Close so we know the value was held.
	before := a.StaticPrivateKey()
	if len(before) != 32 || before[0] != 0xAA {
		t.Fatalf("snapshot before Close: %x", before)
	}

	if err := a.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	after := a.StaticPrivateKey()
	if len(after) != 0 {
		t.Errorf("StaticPrivateKey after Close = %x (len %d), want empty", after, len(after))
	}
}

func TestTPMAttester_CloseIsIdempotent(t *testing.T) {
	a, _ := NewTPM(TPMConfig{TPM: &fakeTPM{}, StaticPrivateKey: make([]byte, 32)})
	if err := a.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestTPMAttester_CloseOnNilIsSafe(t *testing.T) {
	var a *TPMAttester
	if err := a.Close(); err != nil {
		t.Errorf("Close on nil receiver: %v", err)
	}
}
