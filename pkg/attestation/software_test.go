package attestation

import (
	"context"
	"crypto/ed25519"
	"testing"
)

func TestNewSoftware_HappyPath(t *testing.T) {
	a, err := NewSoftware(SoftwareConfig{})
	if err != nil {
		t.Fatalf("NewSoftware: %v", err)
	}
	if a.Type() != "software" {
		t.Errorf("Type = %q", a.Type())
	}
	if len(a.PublicKey()) != 32 {
		t.Errorf("PublicKey len = %d", len(a.PublicKey()))
	}
	if len(a.StaticPrivateKey()) != 32 {
		t.Errorf("StaticPrivateKey len = %d", len(a.StaticPrivateKey()))
	}
	if len(a.SignerPublic()) != ed25519.PublicKeySize {
		t.Errorf("SignerPublic len = %d", len(a.SignerPublic()))
	}
}

func TestNewSoftware_AcceptsSuppliedKeys(t *testing.T) {
	_, signerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	staticPriv := make([]byte, 32)
	staticPriv[31] = 1 // arbitrary fixed key
	a, err := NewSoftware(SoftwareConfig{
		SignerPrivateKey: signerPriv,
		StaticPrivateKey: staticPriv,
	})
	if err != nil {
		t.Fatalf("NewSoftware: %v", err)
	}
	if got := a.StaticPrivateKey(); got[31] != 1 {
		t.Errorf("static priv not preserved: %v", got)
	}
}

func TestNewSoftware_RejectsWrongLengths(t *testing.T) {
	if _, err := NewSoftware(SoftwareConfig{StaticPrivateKey: make([]byte, 31)}); err == nil {
		t.Error("expected error on short static priv")
	}
	if _, err := NewSoftware(SoftwareConfig{SignerPrivateKey: ed25519.PrivateKey(make([]byte, 31))}); err == nil {
		t.Error("expected error on short signer priv")
	}
}

func TestAttest_VerifiesUnderSignerPublic(t *testing.T) {
	a, err := NewSoftware(SoftwareConfig{})
	if err != nil {
		t.Fatalf("NewSoftware: %v", err)
	}
	ev, err := a.Attest(context.Background(), []byte("hello"))
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if len(ev.Evidence) == 0 || len(ev.Endorsement) == 0 {
		t.Error("evidence/endorsement empty")
	}
	staticPub, boundData, err := VerifySoftwareEvidence(ev.Evidence, ev.Endorsement)
	if err != nil {
		t.Fatalf("VerifySoftwareEvidence: %v", err)
	}
	if string(boundData) != "hello" {
		t.Errorf("boundData round-trip = %q", boundData)
	}
	want := a.PublicKey()
	if string(staticPub) != string(want) {
		t.Errorf("staticPub round-trip mismatch")
	}
}

func TestAttest_DeterministicGivenSameInputs(t *testing.T) {
	a, _ := NewSoftware(SoftwareConfig{})
	a1, _ := a.Attest(context.Background(), []byte("payload"))
	a2, _ := a.Attest(context.Background(), []byte("payload"))
	if string(a1.Evidence) != string(a2.Evidence) {
		t.Error("two Attest calls with same inputs must produce identical bytes")
	}
}

func TestVerifySoftwareEvidence_RejectsTamperedPayload(t *testing.T) {
	a, _ := NewSoftware(SoftwareConfig{})
	ev, _ := a.Attest(context.Background(), []byte("payload"))
	tampered := append([]byte(nil), ev.Evidence...)
	tampered[40] ^= 0xff // flip a bit in boundData
	if _, _, err := VerifySoftwareEvidence(tampered, ev.Endorsement); err == nil {
		t.Error("expected verification failure for tampered evidence")
	}
}

func TestVerifySoftwareEvidence_RejectsWrongSigner(t *testing.T) {
	a, _ := NewSoftware(SoftwareConfig{})
	ev, _ := a.Attest(context.Background(), []byte("payload"))
	other, _, _ := ed25519.GenerateKey(nil)
	if _, _, err := VerifySoftwareEvidence(ev.Evidence, other); err == nil {
		t.Error("expected verification failure under wrong signer pub")
	}
}

func TestVerifySoftwareEvidence_RejectsBadEnvelope(t *testing.T) {
	if _, _, err := VerifySoftwareEvidence(make([]byte, 10), make([]byte, 32)); err == nil {
		t.Error("expected too-short envelope rejection")
	}
	good, _ := NewSoftware(SoftwareConfig{})
	ev, _ := good.Attest(context.Background(), []byte("x"))
	if _, _, err := VerifySoftwareEvidence(ev.Evidence, make([]byte, 31)); err == nil {
		t.Error("expected wrong-size signer pub rejection")
	}
	// Bad length field
	bad := append([]byte(nil), ev.Evidence...)
	bad[35] = 0xff
	if _, _, err := VerifySoftwareEvidence(bad, ev.Endorsement); err == nil {
		t.Error("expected length-mismatch rejection")
	}
}
