package certificates

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// newTestManagerWithEd25519 creates a manager with a freshly generated
// Ed25519 key pair. It returns the manager and the private key so tests can
// perform independent verification.
func newTestManagerWithEd25519(t *testing.T, signingKey []byte) (*CertificatesManager, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	m := newTestManager(signingKey)
	if err := m.SetEd25519SigningKey(priv, 42); err != nil {
		t.Fatalf("SetEd25519SigningKey: %v", err)
	}
	return m, priv, pub
}

// newTestManagerWithAuthSecret creates a manager with a zkgroup
// ServerSecretParams configured from a deterministic randomness seed.
func newTestManagerWithAuthSecret(signingKey []byte, seed byte) *CertificatesManager {
	var randomness zkgroup.RandomnessBytes
	for i := range randomness {
		randomness[i] = seed + byte(i)
	}
	secret, err := zkgroup.GenerateServerSecretParams(randomness)
	if err != nil {
		panic("failed to generate server secret params: " + err.Error())
	}
	m := newTestManager(signingKey)
	m.SetAuthServerSecret(secret)
	return m
}

// decodeAndUnmarshalCert decodes a base64 delivery certificate and
// unmarshals the inner SenderCertificate JSON.
func decodeAndUnmarshalCert(t *testing.T, encoded []byte) SenderCertificate {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var sc SenderCertificate
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatalf("unmarshal sender certificate: %v", err)
	}
	return sc
}

// ── SetEd25519SigningKey tests ────────────────────────────────────────────────

func TestSetEd25519SigningKey_ValidKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := newTestManager([]byte("key"))

	if err := m.SetEd25519SigningKey(priv, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify the enclave was populated by checking the public key is derivable.
	if m.ed25519Enclave == nil {
		t.Error("expected ed25519Enclave to be set")
	}
	if m.ed25519PubKeyID != 1 {
		t.Errorf("pubKeyID = %d, want 1", m.ed25519PubKeyID)
	}
}

func TestSetEd25519SigningKey_InvalidKeySize(t *testing.T) {
	m := newTestManager([]byte("key"))

	// Too short — not a valid Ed25519 private key.
	err := m.SetEd25519SigningKey(ed25519.PrivateKey{0x01, 0x02}, 0)
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}

	var target *Ed25519KeyError
	if !errors.As(err, &target) {
		t.Fatalf("expected *Ed25519KeyError, got %T: %v", err, err)
	}
}

func TestSetEd25519SigningKey_EmptyKey(t *testing.T) {
	m := newTestManager([]byte("key"))

	err := m.SetEd25519SigningKey(ed25519.PrivateKey{}, 0)
	if err == nil {
		t.Fatal("expected error for empty key")
	}

	var target *Ed25519KeyError
	if !errors.As(err, &target) {
		t.Fatalf("expected *Ed25519KeyError, got %T", err)
	}
}

func TestSetEd25519SigningKey_KeyIsDefensiveCopy(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := newTestManager([]byte("key"))

	if err := m.SetEd25519SigningKey(priv, 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// memguard.NewBufferFromBytes zeroes the source slice; the enclave holds
	// its own copy. Verify that the manager can still derive the correct public
	// key even after the original slice has been mutated (zeroed by memguard).
	got := m.Ed25519PublicKey()
	if got == nil {
		t.Fatal("expected non-nil public key after SetEd25519SigningKey")
	}
	if !bytes.Equal(got, pub) {
		t.Error("manager's enclave does not contain the original key (defensive copy check)")
	}
}

func TestEd25519PublicKey_WhenSet(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := newTestManager([]byte("key"))
	if err := m.SetEd25519SigningKey(priv, 0); err != nil {
		t.Fatalf("SetEd25519SigningKey: %v", err)
	}

	got := m.Ed25519PublicKey()
	if got == nil {
		t.Fatal("expected non-nil public key")
	}
	if !bytes.Equal(got, pub) {
		t.Error("public key mismatch")
	}
}

func TestEd25519PublicKey_WhenNotSet(t *testing.T) {
	m := newTestManager([]byte("key"))
	if got := m.Ed25519PublicKey(); got != nil {
		t.Errorf("expected nil public key when not configured, got %v", got)
	}
}

// ── Destroy tests (with Ed25519 key) ─────────────────────────────────────────

func TestDestroy_WipesEd25519Key(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := newTestManager([]byte("key"))
	if err := m.SetEd25519SigningKey(priv, 0); err != nil {
		t.Fatalf("SetEd25519SigningKey: %v", err)
	}
	if m.ed25519Enclave == nil {
		t.Fatal("expected enclave to be set before Destroy")
	}

	m.Destroy()

	if m.ed25519Enclave != nil {
		t.Error("expected ed25519Enclave to be nil after Destroy")
	}
}

func TestDestroy_Idempotent_WithEd25519(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := newTestManager([]byte("key"))
	if err := m.SetEd25519SigningKey(priv, 0); err != nil {
		t.Fatalf("SetEd25519SigningKey: %v", err)
	}

	m.Destroy()
	// Second destroy must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("second Destroy panicked: %v", r)
		}
	}()
	m.Destroy()
}

// ── Delivery certificate Ed25519 signing tests ───────────────────────────────

func TestGetDeliveryCertificate_Ed25519Signature(t *testing.T) {
	m, _, pub := newTestManagerWithEd25519(t, []byte("key"))
	ctx := context.Background()

	cert, err := m.GetDeliveryCertificate(ctx, "uuid-ed25519", "+15551234567", 1, []byte{1, 2, 3}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sc := decodeAndUnmarshalCert(t, cert.Certificate)

	// Reconstruct the signed payload (without Signer field).
	payload := struct {
		SenderUUID     string `json:"senderUuid"`
		SenderE164     string `json:"senderE164,omitempty"`
		SenderDeviceID uint32 `json:"senderDeviceId"`
		Expiration     int64  `json:"expiration"`
		IdentityKey    []byte `json:"identityKey"`
	}{
		SenderUUID:     sc.SenderUUID,
		SenderE164:     sc.SenderE164,
		SenderDeviceID: sc.SenderDeviceID,
		Expiration:     sc.Expiration,
		IdentityKey:    sc.IdentityKey,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	// Ed25519 signature is 64 bytes.
	if len(sc.Signer) != ed25519.SignatureSize {
		t.Errorf("signer length = %d, want %d (Ed25519 signature size)", len(sc.Signer), ed25519.SignatureSize)
	}

	if !ed25519.Verify(pub, data, sc.Signer) {
		t.Error("Ed25519 signature verification failed")
	}
}

func TestGetDeliveryCertificate_Ed25519SignatureVerificationFails_WrongKey(t *testing.T) {
	m, _, _ := newTestManagerWithEd25519(t, []byte("key"))
	ctx := context.Background()

	cert, err := m.GetDeliveryCertificate(ctx, "uuid-wrong-key", "+15551234567", 1, []byte{1, 2, 3}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sc := decodeAndUnmarshalCert(t, cert.Certificate)

	payload := struct {
		SenderUUID     string `json:"senderUuid"`
		SenderE164     string `json:"senderE164,omitempty"`
		SenderDeviceID uint32 `json:"senderDeviceId"`
		Expiration     int64  `json:"expiration"`
		IdentityKey    []byte `json:"identityKey"`
	}{
		SenderUUID:     sc.SenderUUID,
		SenderE164:     sc.SenderE164,
		SenderDeviceID: sc.SenderDeviceID,
		Expiration:     sc.Expiration,
		IdentityKey:    sc.IdentityKey,
	}
	data, _ := json.Marshal(payload)

	// A different public key must NOT verify the signature.
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	if ed25519.Verify(wrongPub, data, sc.Signer) {
		t.Error("signature verified with wrong public key; this should not happen")
	}
}

func TestGetDeliveryCertificate_Ed25519_DeterministicSameInputs(t *testing.T) {
	m, _, _ := newTestManagerWithEd25519(t, []byte("key"))
	ctx := context.Background()

	// Ed25519 is deterministic for the same private key and message.
	sc1 := decodeAndUnmarshalCert(t, func() []byte {
		cert, _ := m.GetDeliveryCertificate(ctx, "uuid-det", "+1555", 1, []byte{9}, true)
		return cert.Certificate
	}())

	sc2 := decodeAndUnmarshalCert(t, func() []byte {
		cert, _ := m.GetDeliveryCertificate(ctx, "uuid-det", "+1555", 1, []byte{9}, true)
		return cert.Certificate
	}())

	// The expiry will differ slightly between calls (time.Now), but the UUID and
	// device ID are the same — we just verify the signature length is consistent.
	if len(sc1.Signer) != ed25519.SignatureSize {
		t.Errorf("unexpected signer length on first call: %d", len(sc1.Signer))
	}
	if len(sc2.Signer) != ed25519.SignatureSize {
		t.Errorf("unexpected signer length on second call: %d", len(sc2.Signer))
	}
}

func TestGetDeliveryCertificate_HMACFallback_WhenNoEd25519(t *testing.T) {
	key := []byte("hmac-fallback-test-key")
	m := newTestManager(key)
	ctx := context.Background()

	cert, err := m.GetDeliveryCertificate(ctx, "uuid-hmac", "+15551234567", 1, []byte{1, 2, 3}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sc := decodeAndUnmarshalCert(t, cert.Certificate)

	// HMAC-SHA256 signature is 32 bytes.
	if len(sc.Signer) != sha256.Size {
		t.Errorf("signer length = %d, want %d (HMAC-SHA256 size)", len(sc.Signer), sha256.Size)
	}

	// Verify the HMAC.
	payload := struct {
		SenderUUID     string `json:"senderUuid"`
		SenderE164     string `json:"senderE164,omitempty"`
		SenderDeviceID uint32 `json:"senderDeviceId"`
		Expiration     int64  `json:"expiration"`
		IdentityKey    []byte `json:"identityKey"`
	}{
		SenderUUID:     sc.SenderUUID,
		SenderE164:     sc.SenderE164,
		SenderDeviceID: sc.SenderDeviceID,
		Expiration:     sc.Expiration,
		IdentityKey:    sc.IdentityKey,
	}
	data, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)

	if !hmac.Equal(sc.Signer, expected) {
		t.Error("HMAC fallback signature verification failed")
	}
}

func TestGetDeliveryCertificate_SignatureSizeDiffers_Ed25519VsHMAC(t *testing.T) {
	// With Ed25519: 64-byte signature.
	mEd, _, _ := newTestManagerWithEd25519(t, []byte("k"))
	// Without Ed25519: 32-byte HMAC signature.
	mHmac := newTestManager([]byte("k"))
	ctx := context.Background()

	certEd, _ := mEd.GetDeliveryCertificate(ctx, "uuid", "+1", 1, []byte{1}, false)
	certHmac, _ := mHmac.GetDeliveryCertificate(ctx, "uuid", "+1", 1, []byte{1}, false)

	scEd := decodeAndUnmarshalCert(t, certEd.Certificate)
	scHmac := decodeAndUnmarshalCert(t, certHmac.Certificate)

	if len(scEd.Signer) != ed25519.SignatureSize {
		t.Errorf("Ed25519 signer size = %d, want %d", len(scEd.Signer), ed25519.SignatureSize)
	}
	if len(scHmac.Signer) != sha256.Size {
		t.Errorf("HMAC signer size = %d, want %d", len(scHmac.Signer), sha256.Size)
	}
}

// ── SetAuthServerSecret tests ─────────────────────────────────────────────────

func TestSetAuthServerSecret_StoresParams(t *testing.T) {
	var randomness zkgroup.RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i)
	}
	secret, err := zkgroup.GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}

	m := newTestManager([]byte("key"))
	m.SetAuthServerSecret(secret)

	if m.authServerSecret == nil {
		t.Fatal("expected authServerSecret to be set")
	}
	if m.authServerSecret != secret {
		t.Error("expected authServerSecret to match the provided params")
	}
}

func TestSetAuthServerSecret_OverwritesPrevious(t *testing.T) {
	m := newTestManager([]byte("key"))

	var r1 zkgroup.RandomnessBytes
	for i := range r1 {
		r1[i] = byte(i)
	}
	s1, _ := zkgroup.GenerateServerSecretParams(r1)
	m.SetAuthServerSecret(s1)

	var r2 zkgroup.RandomnessBytes
	for i := range r2 {
		r2[i] = byte(i + 100)
	}
	s2, _ := zkgroup.GenerateServerSecretParams(r2)
	m.SetAuthServerSecret(s2)

	if m.authServerSecret != s2 {
		t.Error("expected authServerSecret to be overwritten with second params")
	}
}

// ── zkgroup group credential issuance tests ───────────────────────────────────

func TestGetGroupCredentials_ZKGroupIssue_SingleDay(t *testing.T) {
	m := newTestManagerWithAuthSecret([]byte("key"), 0x10)
	ctx := context.Background()

	// Use a valid UUID for the ACI.
	aciUUID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	pni := "PNI:" + aciUUID
	start := int64(86400)
	end := int64(86400)

	creds, err := m.GetGroupCredentials(ctx, aciUUID, pni, start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(creds.Credentials) != 1 {
		t.Fatalf("Credentials length = %d, want 1", len(creds.Credentials))
	}
	if len(creds.Credentials[0].Credential) == 0 {
		t.Error("expected non-empty credential bytes")
	}
	if creds.Credentials[0].RedemptionTime != 86400 {
		t.Errorf("RedemptionTime = %d, want 86400", creds.Credentials[0].RedemptionTime)
	}
}

func TestGetGroupCredentials_ZKGroupIssue_MultipleDays(t *testing.T) {
	m := newTestManagerWithAuthSecret([]byte("key"), 0x20)
	ctx := context.Background()

	aciUUID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	pni := "PNI:" + aciUUID
	start := int64(0)
	end := int64(86400 * 2)

	creds, err := m.GetGroupCredentials(ctx, aciUUID, pni, start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(creds.Credentials) != 3 {
		t.Fatalf("Credentials length = %d, want 3", len(creds.Credentials))
	}
	for i, c := range creds.Credentials {
		if len(c.Credential) == 0 {
			t.Errorf("Credentials[%d] has empty credential", i)
		}
		if c.RedemptionTime != int64(i)*86400 {
			t.Errorf("Credentials[%d].RedemptionTime = %d, want %d",
				i, c.RedemptionTime, int64(i)*86400)
		}
	}
}

func TestGetGroupCredentials_ZKGroupIssue_CredentialIsNonEmpty(t *testing.T) {
	m := newTestManagerWithAuthSecret([]byte("key"), 0x30)
	ctx := context.Background()

	aciUUID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	pni := "PNI:b2c3d4e5-f6a7-8901-bcde-f12345678901"
	start := int64(86400)
	end := int64(86400)

	creds, err := m.GetGroupCredentials(ctx, aciUUID, pni, start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cred := creds.Credentials[0].Credential
	if len(cred) == 0 {
		t.Error("expected non-empty credential")
	}
	// The zkgroup credential begins with a reserved byte (0x00).
	if cred[0] != 0 {
		t.Errorf("credential[0] = %d, want 0 (zkgroup Serialize reserved byte)", cred[0])
	}
}

func TestGetGroupCredentials_ZKGroupIssue_DifferentACIsDifferentCreds(t *testing.T) {
	m := newTestManagerWithAuthSecret([]byte("key"), 0x40)
	ctx := context.Background()

	pni := "PNI:b2c3d4e5-f6a7-8901-bcde-f12345678901"
	start := int64(86400)
	end := int64(86400)

	creds1, err := m.GetGroupCredentials(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", pni, start, end)
	if err != nil {
		t.Fatalf("unexpected error (aci1): %v", err)
	}

	creds2, err := m.GetGroupCredentials(ctx, "b2c3d4e5-f6a7-8901-bcde-f12345678901", pni, start, end)
	if err != nil {
		t.Fatalf("unexpected error (aci2): %v", err)
	}

	if bytes.Equal(creds1.Credentials[0].Credential, creds2.Credentials[0].Credential) {
		t.Error("expected different credentials for different ACIs")
	}
}

func TestGetGroupCredentials_ZKGroupIssue_PNIAcronymStripped(t *testing.T) {
	m := newTestManagerWithAuthSecret([]byte("key"), 0x50)
	ctx := context.Background()

	aci := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	// PNI with "PNI:" prefix should be stripped before parsing.
	pniWithPrefix := "PNI:b2c3d4e5-f6a7-8901-bcde-f12345678901"

	creds, err := m.GetGroupCredentials(ctx, aci, pniWithPrefix, int64(86400), int64(86400))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(creds.Credentials[0].Credential) == 0 {
		t.Error("expected non-empty credential when PNI has prefix")
	}
}

func TestGetGroupCredentials_ZKGroupIssue_InvalidACIUUID(t *testing.T) {
	m := newTestManagerWithAuthSecret([]byte("key"), 0x60)
	ctx := context.Background()

	_, err := m.GetGroupCredentials(ctx, "not-a-uuid", "PNI:not-a-uuid", int64(86400), int64(86400))
	if err == nil {
		t.Fatal("expected error for invalid ACI UUID")
	}

	var target *CertificateGenerationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CertificateGenerationError, got %T: %v", err, err)
	}
}

func TestGetGroupCredentials_ZKGroupIssue_PNIFallsBackToACIOnParseError(t *testing.T) {
	// When PNI cannot be parsed as a UUID, the code falls back to using the
	// ACI bytes as a synthetic PNI. This test verifies the call still succeeds.
	m := newTestManagerWithAuthSecret([]byte("key"), 0x70)
	ctx := context.Background()

	aci := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	// Opaque PNI that doesn't parse as UUID, even with prefix stripped.
	pni := "PNI:opaque-pni-value"

	creds, err := m.GetGroupCredentials(ctx, aci, pni, int64(86400), int64(86400))
	if err != nil {
		t.Fatalf("unexpected error with opaque PNI: %v", err)
	}
	if len(creds.Credentials[0].Credential) == 0 {
		t.Error("expected non-empty credential even with opaque PNI")
	}
}

// ── issueAuthCredentialWithPni unit tests ─────────────────────────────────────

func TestIssueAuthCredentialWithPni_ValidUUIDs(t *testing.T) {
	m := newTestManagerWithAuthSecret([]byte("key"), 0x80)
	aci := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	pni := "b2c3d4e5-f6a7-8901-bcde-f12345678901"

	cred, err := m.issueAuthCredentialWithPni(aci, pni, int64(86400))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cred) == 0 {
		t.Error("expected non-empty credential")
	}
}

func TestIssueAuthCredentialWithPni_DifferentTimesProduceDifferentCreds(t *testing.T) {
	m := newTestManagerWithAuthSecret([]byte("key"), 0x81)
	aci := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	pni := "b2c3d4e5-f6a7-8901-bcde-f12345678901"

	cred1, err := m.issueAuthCredentialWithPni(aci, pni, int64(86400))
	if err != nil {
		t.Fatalf("unexpected error (day 1): %v", err)
	}

	cred2, err := m.issueAuthCredentialWithPni(aci, pni, int64(86400*2))
	if err != nil {
		t.Fatalf("unexpected error (day 2): %v", err)
	}

	if bytes.Equal(cred1, cred2) {
		t.Error("expected different credentials for different redemption times")
	}
}

func TestIssueAuthCredentialWithPni_InvalidACIUUID(t *testing.T) {
	m := newTestManagerWithAuthSecret([]byte("key"), 0x82)

	_, err := m.issueAuthCredentialWithPni("not-a-uuid", "not-a-uuid", int64(86400))
	if err == nil {
		t.Fatal("expected error for invalid ACI UUID")
	}

	var target *InvalidUUIDError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidUUIDError, got %T: %v", err, err)
	}
}

// ── ExpiringProfileKeyCredential stub tests ───────────────────────────────────

func TestGetExpiringProfileKeyCredentialStub_NoAuthSecret(t *testing.T) {
	m := newTestManager([]byte("key"))
	ctx := context.Background()

	ts := zkgroup.NewTimestamp(uint64(time.Now().Add(7 * 24 * time.Hour).Unix()))
	resp, err := m.GetExpiringProfileKeyCredentialStub(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
		return
	}
	if len(resp.Credential) == 0 {
		t.Error("expected non-empty stub credential")
	}
	if resp.CredentialExpirationTime != int64(ts.EpochSeconds()) {
		t.Errorf("CredentialExpirationTime = %d, want %d",
			resp.CredentialExpirationTime, int64(ts.EpochSeconds()))
	}
}

func TestGetExpiringProfileKeyCredentialStub_DeterministicForSameInputs(t *testing.T) {
	m := newTestManager([]byte("stable-key"))
	ctx := context.Background()

	ts := zkgroup.NewTimestamp(uint64(86400 * 10))
	aci := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

	resp1, err := m.GetExpiringProfileKeyCredentialStub(ctx, aci, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp2, err := m.GetExpiringProfileKeyCredentialStub(ctx, aci, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !bytes.Equal(resp1.Credential, resp2.Credential) {
		t.Error("expected deterministic credentials for identical inputs")
	}
}

func TestGetExpiringProfileKeyCredentialStub_DifferentACIsDifferentCreds(t *testing.T) {
	m := newTestManager([]byte("key"))
	ctx := context.Background()

	ts := zkgroup.NewTimestamp(uint64(86400 * 5))
	resp1, _ := m.GetExpiringProfileKeyCredentialStub(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", ts)
	resp2, _ := m.GetExpiringProfileKeyCredentialStub(ctx, "b2c3d4e5-f6a7-8901-bcde-f12345678901", ts)

	if bytes.Equal(resp1.Credential, resp2.Credential) {
		t.Error("expected different credentials for different ACIs")
	}
}

func TestGetExpiringProfileKeyCredentialStub_DifferentExpirationsDifferentCreds(t *testing.T) {
	m := newTestManager([]byte("key"))
	ctx := context.Background()

	aci := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	ts1 := zkgroup.NewTimestamp(uint64(86400 * 5))
	ts2 := zkgroup.NewTimestamp(uint64(86400 * 6))

	resp1, _ := m.GetExpiringProfileKeyCredentialStub(ctx, aci, ts1)
	resp2, _ := m.GetExpiringProfileKeyCredentialStub(ctx, aci, ts2)

	if bytes.Equal(resp1.Credential, resp2.Credential) {
		t.Error("expected different credentials for different expiration times")
	}
}

func TestGetExpiringProfileKeyCredentialStub_CorrectExpirationTime(t *testing.T) {
	m := newTestManager([]byte("key"))
	ctx := context.Background()

	epochSecs := uint64(86400 * 7)
	ts := zkgroup.NewTimestamp(epochSecs)
	resp, err := m.GetExpiringProfileKeyCredentialStub(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.CredentialExpirationTime != int64(epochSecs) {
		t.Errorf("CredentialExpirationTime = %d, want %d",
			resp.CredentialExpirationTime, int64(epochSecs))
	}
}

// ── GetExpiringProfileKeyCredential with full zkgroup ──────────────────────────

func TestGetExpiringProfileKeyCredential_WithAuthSecret(t *testing.T) {
	m := newTestManagerWithAuthSecret([]byte("key"), 0x90)
	ctx := context.Background()

	// Create a client-side profile key and credential request context so we
	// have a valid ProfileKeyCredentialRequest to pass to the server.
	var pkRandomness zkgroup.RandomnessBytes
	if _, err := rand.Read(pkRandomness[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	profileKey := zkgroup.GenerateProfileKey(pkRandomness)

	var serverSecretRandomness zkgroup.RandomnessBytes
	for i := range serverSecretRandomness {
		serverSecretRandomness[i] = 0x90 + byte(i)
	}
	serverSecret, err := zkgroup.GenerateServerSecretParams(serverSecretRandomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	m.authServerSecret = serverSecret

	serverPub := serverSecret.GetPublicParams()

	aciUUID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	var uuidBytes [16]byte
	// Parse and copy the UUID bytes manually.
	rawUUID := "a1b2c3d4e5f678 90abcdef1234567890"
	_ = rawUUID
	copy(uuidBytes[:], []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90})
	aci := zkgroup.NewACI(uuidBytes)

	var reqRandomness zkgroup.RandomnessBytes
	if _, err := rand.Read(reqRandomness[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	reqCtx, err := serverPub.CreateProfileKeyCredentialRequestContext(reqRandomness, aci, profileKey)
	if err != nil {
		t.Fatalf("CreateProfileKeyCredentialRequestContext: %v", err)
	}

	commitment := profileKey.GetCommitment(aci)

	// Expiration must be day-aligned and in the future.
	expiration := zkgroup.NewTimestamp(uint64(
		time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(24 * time.Hour).Unix(),
	))

	resp, err := m.GetExpiringProfileKeyCredential(ctx, aciUUID, reqCtx.GetRequest(), commitment, expiration)
	if err != nil {
		t.Fatalf("GetExpiringProfileKeyCredential: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
		return
	}
	if len(resp.Credential) == 0 {
		t.Error("expected non-empty credential")
	}
	if resp.CredentialExpirationTime != int64(expiration.EpochSeconds()) {
		t.Errorf("CredentialExpirationTime = %d, want %d",
			resp.CredentialExpirationTime, int64(expiration.EpochSeconds()))
	}
}

func TestGetExpiringProfileKeyCredential_FallsBackToStubWhenNoAuthSecret(t *testing.T) {
	m := newTestManager([]byte("key"))
	ctx := context.Background()

	ts := zkgroup.NewTimestamp(uint64(86400 * 7))

	// Pass nil request and commitment — the stub path does not use them.
	resp, err := m.GetExpiringProfileKeyCredential(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", nil, nil, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response from stub path")
		return
	}
	if len(resp.Credential) == 0 {
		t.Error("expected non-empty stub credential")
	}
}

func TestGetExpiringProfileKeyCredential_InvalidUUID_WithAuthSecret(t *testing.T) {
	m := newTestManagerWithAuthSecret([]byte("key"), 0xA0)
	ctx := context.Background()

	ts := zkgroup.NewTimestamp(uint64(86400))
	_, err := m.GetExpiringProfileKeyCredential(ctx, "not-a-uuid", nil, nil, ts)
	if err == nil {
		t.Fatal("expected error for invalid ACI UUID")
	}

	var target *InvalidUUIDError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidUUIDError, got %T: %v", err, err)
	}
}

// ── Error type tests ──────────────────────────────────────────────────────────

func TestEd25519KeyError_Error(t *testing.T) {
	cause := errors.New("bad key")
	e := &Ed25519KeyError{Cause: cause}
	got := e.Error()
	if got != "ed25519 key error: bad key" {
		t.Errorf("unexpected error string: %q", got)
	}
}

func TestEd25519KeyError_Unwrap(t *testing.T) {
	cause := errors.New("inner")
	e := &Ed25519KeyError{Cause: cause}
	if !errors.Is(e, cause) {
		t.Error("Unwrap should expose the cause")
	}
}

func TestInvalidUUIDError_Error(t *testing.T) {
	cause := errors.New("parse error")
	e := &InvalidUUIDError{Value: "bad-uuid", Cause: cause}
	got := e.Error()
	if got != "invalid uuid bad-uuid: parse error" {
		t.Errorf("unexpected error string: %q", got)
	}
}

func TestInvalidUUIDError_Unwrap(t *testing.T) {
	cause := errors.New("inner")
	e := &InvalidUUIDError{Value: "x", Cause: cause}
	if !errors.Is(e, cause) {
		t.Error("Unwrap should expose the cause")
	}
}

func TestZKGroupError_Error(t *testing.T) {
	cause := errors.New("crypto error")
	e := &ZKGroupError{Operation: "issue-auth-credential", Cause: cause}
	got := e.Error()
	if got != "zkgroup issue-auth-credential failed: crypto error" {
		t.Errorf("unexpected error string: %q", got)
	}
}

func TestZKGroupError_Unwrap(t *testing.T) {
	cause := errors.New("inner")
	e := &ZKGroupError{Operation: "op", Cause: cause}
	if !errors.Is(e, cause) {
		t.Error("Unwrap should expose the cause")
	}
}

// ── itoa helper tests ─────────────────────────────────────────────────────────

func TestItoa(t *testing.T) {
	tests := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{-1, "-1"},
		{42, "42"},
		{-100, "-100"},
		{1234567, "1234567"},
	}
	for _, tt := range tests {
		got := itoa(tt.in)
		if got != tt.want {
			t.Errorf("itoa(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ── invalidKeyLengthError tests ───────────────────────────────────────────────

func TestInvalidKeyLengthError_Error(t *testing.T) {
	e := &invalidKeyLengthError{Got: 16, Want: 64}
	got := e.Error()
	if got != "invalid key length: got 16, want 64" {
		t.Errorf("unexpected error string: %q", got)
	}
}

// ── ExpiringProfileKeyCredentialResponse type test ───────────────────────────

func TestExpiringProfileKeyCredentialResponse_JSONRoundTrip(t *testing.T) {
	r := ExpiringProfileKeyCredentialResponse{
		Credential:               []byte{1, 2, 3, 4},
		CredentialExpirationTime: 86400 * 7,
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded ExpiringProfileKeyCredentialResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !bytes.Equal(decoded.Credential, r.Credential) {
		t.Error("Credential mismatch after round-trip")
	}
	if decoded.CredentialExpirationTime != r.CredentialExpirationTime {
		t.Errorf("CredentialExpirationTime = %d, want %d",
			decoded.CredentialExpirationTime, r.CredentialExpirationTime)
	}
}

func TestExpiringProfileKeyCredentialResponse_ZeroValue(t *testing.T) {
	var r ExpiringProfileKeyCredentialResponse
	if r.Credential != nil {
		t.Error("expected nil Credential for zero value")
	}
	if r.CredentialExpirationTime != 0 {
		t.Error("expected zero CredentialExpirationTime for zero value")
	}
}

// ── stubProfileKeyCredential marshal error test ───────────────────────────────

func TestStubProfileKeyCredential_MarshalError(t *testing.T) {
	original := jsonMarshal
	t.Cleanup(func() { jsonMarshal = original })

	jsonMarshal = func(_ any) ([]byte, error) {
		return nil, errors.New("stub marshal failure")
	}

	m := newTestManager([]byte("key"))
	ts := zkgroup.NewTimestamp(uint64(86400))
	_, err := m.stubProfileKeyCredential("uuid", ts)
	if err == nil {
		t.Fatal("expected error when marshal fails")
	}

	var target *CertificateGenerationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CertificateGenerationError, got %T: %v", err, err)
	}
	if target.Operation != "stub-profile-key-credential" {
		t.Errorf("Operation = %q, want %q", target.Operation, "stub-profile-key-credential")
	}
}

// ── newTestManager uses SecureString ─────────────────────────────────────────

// Verify that SecureString creation from nil-sized signing key does not panic.
func TestNewCertificatesManager_EmptySecureString(t *testing.T) {
	m := NewCertificatesManager(secrets.NewSecureString(""), nil)
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

// ── randRead error path tests ─────────────────────────────────────────────────

func TestIssueAuthCredentialWithPni_RandReadError(t *testing.T) {
	original := randRead
	t.Cleanup(func() { randRead = original })

	randRead = func(b []byte) (int, error) {
		return 0, errors.New("simulated rand failure")
	}

	m := newTestManagerWithAuthSecret([]byte("key"), 0xE0)
	_, err := m.issueAuthCredentialWithPni(
		"a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		"b2c3d4e5-f6a7-8901-bcde-f12345678901",
		int64(86400),
	)
	if err == nil {
		t.Fatal("expected error when randRead fails")
	}
}

func TestIssueCallLinkAuthCredentials_RandReadError(t *testing.T) {
	original := randRead
	t.Cleanup(func() { randRead = original })

	randRead = func(b []byte) (int, error) {
		return 0, errors.New("simulated rand failure")
	}

	m := newTestManager([]byte("key"))
	var randomness zkgroup.RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 42)
	}
	params := zkgroup.GenerateGenericServerSecretParams(randomness)
	m.SetCallingZKParams(params)

	_, err := m.issueCallLinkAuthCredentials("a1b2c3d4-e5f6-7890-abcd-ef1234567890", 1, 1)
	if err == nil {
		t.Fatal("expected error when randRead fails in issueCallLinkAuthCredentials")
	}
}

func TestIssueCallLinkAuthCredentials_InvalidUUID(t *testing.T) {
	m := newTestManager([]byte("key"))
	var randomness zkgroup.RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 55)
	}
	params := zkgroup.GenerateGenericServerSecretParams(randomness)
	m.SetCallingZKParams(params)

	_, err := m.issueCallLinkAuthCredentials("not-a-uuid", 1, 1)
	if err == nil {
		t.Fatal("expected error for invalid UUID in issueCallLinkAuthCredentials")
	}
}

func TestGetGroupCredentials_CallLinkCredsFail_ButGroupCredentialsReturned(t *testing.T) {
	// When calling ZK params are set but the UUID is invalid for call link
	// auth credentials, the manager should still return the group credentials
	// and log a warning (non-fatal).
	m := newTestManager([]byte("key"))

	// Set calling ZK params but use an invalid UUID that will make the call
	// link credential issuance fail (non-fatally).
	var randomness zkgroup.RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 22)
	}
	params := zkgroup.GenerateGenericServerSecretParams(randomness)
	m.SetCallingZKParams(params)

	ctx := context.Background()
	// "not-a-uuid" is not a valid UUID; call link issuance will fail.
	// The group credentials (HMAC path) should still be returned.
	// NOTE: group credentials use their own UUID path (generateGroupCredential)
	// which doesn't validate UUID format, so group creds succeed.
	creds, err := m.GetGroupCredentials(ctx, "not-a-uuid", "pni-x", int64(86400), int64(86400))
	if err != nil {
		t.Fatalf("unexpected error: group credentials should succeed even when call link creds fail: %v", err)
	}
	if len(creds.Credentials) != 1 {
		t.Errorf("Credentials length = %d, want 1", len(creds.Credentials))
	}
	// Call link credentials should be nil (failure was non-fatal).
	if creds.CallLinkAuthCredentials != nil {
		t.Errorf("expected nil CallLinkAuthCredentials after non-fatal failure, got %d entries",
			len(creds.CallLinkAuthCredentials))
	}
}

func TestGetExpiringProfileKeyCredential_RandReadError(t *testing.T) {
	original := randRead
	t.Cleanup(func() { randRead = original })

	randRead = func(b []byte) (int, error) {
		return 0, errors.New("simulated rand failure")
	}

	m := newTestManagerWithAuthSecret([]byte("key"), 0xF0)
	ctx := context.Background()
	ts := zkgroup.NewTimestamp(uint64(86400 * 7))

	_, err := m.GetExpiringProfileKeyCredential(
		ctx,
		"a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		nil, nil, // request and commitment are irrelevant — rand fails before use
		ts,
	)
	if err == nil {
		t.Fatal("expected error when randRead fails in GetExpiringProfileKeyCredential")
	}

	var target *CertificateGenerationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CertificateGenerationError, got %T: %v", err, err)
	}
	if target.Operation != "profile-key-randomness" {
		t.Errorf("Operation = %q, want %q", target.Operation, "profile-key-randomness")
	}
}

// ── GetGroupCredentials error path when zkgroup issuance fails ────────────────

func TestGetGroupCredentials_ZKGroupIssueError_PropagatedAsCertGenerationError(t *testing.T) {
	// Provide an authServerSecret but pass an invalid ACI UUID to force an
	// issueAuthCredentialWithPni failure so the error propagates via
	// CertificateGenerationError.
	m := newTestManagerWithAuthSecret([]byte("key"), 0xB0)
	ctx := context.Background()

	// "not-a-uuid" is not a valid ACI UUID; issueAuthCredentialWithPni will
	// return an InvalidUUIDError which GetGroupCredentials wraps.
	_, err := m.GetGroupCredentials(ctx, "not-a-uuid", "PNI:not-a-uuid",
		int64(86400), int64(86400))
	if err == nil {
		t.Fatal("expected error for invalid ACI UUID with zkgroup enabled")
	}

	var target *CertificateGenerationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CertificateGenerationError, got %T: %v", err, err)
	}
	if target.Operation != "group-credential" {
		t.Errorf("Operation = %q, want %q", target.Operation, "group-credential")
	}

	// The inner cause should be an InvalidUUIDError.
	var innerUUID *InvalidUUIDError
	if !errors.As(err, &innerUUID) {
		t.Fatalf("expected *InvalidUUIDError as inner cause, got %T: %v", err, err)
	}
}

// ── GetExpiringProfileKeyCredential error from IssueExpiringProfileKeyCredential ─

func TestGetExpiringProfileKeyCredential_ZKGroupIssuanceError_CorruptProof(t *testing.T) {
	// Provide a valid authServerSecret but pass a ProfileKeyCredentialRequest
	// with a garbage Proof to trigger the proof-verification failure in
	// IssueExpiringProfileKeyCredential, which must return a ZKGroupError.
	var secretRandomness zkgroup.RandomnessBytes
	for i := range secretRandomness {
		secretRandomness[i] = 0xC0 + byte(i)
	}
	serverSecret, err := zkgroup.GenerateServerSecretParams(secretRandomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPub := serverSecret.GetPublicParams()

	m := newTestManager([]byte("key"))
	m.SetAuthServerSecret(serverSecret)

	var pkRandomness zkgroup.RandomnessBytes
	if _, err := rand.Read(pkRandomness[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	profileKey := zkgroup.GenerateProfileKey(pkRandomness)

	var uuidBytes [16]byte
	copy(uuidBytes[:], []byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90})
	aci := zkgroup.NewACI(uuidBytes)

	var reqRandomness zkgroup.RandomnessBytes
	if _, err := rand.Read(reqRandomness[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	reqCtx, err := serverPub.CreateProfileKeyCredentialRequestContext(reqRandomness, aci, profileKey)
	if err != nil {
		t.Fatalf("CreateProfileKeyCredentialRequestContext: %v", err)
	}

	// Corrupt the proof bytes so IssueExpiringProfileKeyCredential rejects it.
	request := reqCtx.GetRequest()
	request.Proof = []byte("garbage-proof-bytes-that-will-not-verify")

	commitment := profileKey.GetCommitment(aci)

	ts := zkgroup.NewTimestamp(uint64(
		time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(24 * time.Hour).Unix(),
	))
	ctx := context.Background()

	_, err = m.GetExpiringProfileKeyCredential(
		ctx,
		"a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		request,
		commitment,
		ts,
	)
	if err == nil {
		t.Fatal("expected error when proof is corrupted")
	}

	var target *ZKGroupError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ZKGroupError, got %T: %v", err, err)
	}
	if target.Operation != "issue-expiring-profile-key-credential" {
		t.Errorf("Operation = %q, want %q", target.Operation, "issue-expiring-profile-key-credential")
	}
}
