package certificates

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// marshalError is a typed error returned by the test marshal stub.
type marshalError struct {
	Message string
}

func (e *marshalError) Error() string {
	return "marshal error: " + e.Message
}

func TestGetDeliveryCertificate_ExpiryIsApprox24Hours(t *testing.T) {
	m := newTestManager([]byte("expiry-key"))
	ctx := context.Background()

	before := time.Now().Add(certificateValidityDuration)
	cert, err := m.GetDeliveryCertificate(ctx, "uuid", "+1555", 1, []byte{1}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	after := time.Now().Add(certificateValidityDuration)

	beforeMillis := before.UnixMilli()
	afterMillis := after.UnixMilli()

	if cert.CertificateExpiry < beforeMillis || cert.CertificateExpiry > afterMillis {
		t.Errorf("CertificateExpiry = %d, expected between %d and %d",
			cert.CertificateExpiry, beforeMillis, afterMillis)
	}
}

func TestGetDeliveryCertificate_CertificateContainsExpiration(t *testing.T) {
	m := newTestManager([]byte("expiry-content-key"))
	ctx := context.Background()

	cert, err := m.GetDeliveryCertificate(ctx, "uuid-exp", "+1555", 1, []byte{1, 2}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(cert.Certificate))
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	var sc SenderCertificate
	if err := json.Unmarshal(decoded, &sc); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if sc.Expiration != cert.CertificateExpiry {
		t.Errorf("SenderCertificate.Expiration = %d, want %d (CertificateExpiry)",
			sc.Expiration, cert.CertificateExpiry)
	}
}

func TestGetDeliveryCertificate_IdentityKeyPreserved(t *testing.T) {
	m := newTestManager([]byte("identity-key"))
	ctx := context.Background()
	identityKey := []byte{0xAA, 0xBB, 0xCC, 0xDD}

	cert, err := m.GetDeliveryCertificate(ctx, "uuid-ik", "+1555", 3, identityKey, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(cert.Certificate))
	if err != nil {
		t.Fatalf("failed to decode: %v", err)
	}

	var sc SenderCertificate
	if err := json.Unmarshal(decoded, &sc); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(sc.IdentityKey) != len(identityKey) {
		t.Fatalf("IdentityKey length = %d, want %d", len(sc.IdentityKey), len(identityKey))
	}
	for i := range identityKey {
		if sc.IdentityKey[i] != identityKey[i] {
			t.Errorf("IdentityKey[%d] = %x, want %x", i, sc.IdentityKey[i], identityKey[i])
		}
	}
}

func TestGetDeliveryCertificate_DeviceIDPreserved(t *testing.T) {
	m := newTestManager([]byte("device-key"))
	ctx := context.Background()

	deviceIDs := []uint32{0, 1, 2, 100, 4294967295}
	for _, did := range deviceIDs {
		cert, err := m.GetDeliveryCertificate(ctx, "uuid-did", "+1555", did, []byte{1}, true)
		if err != nil {
			t.Fatalf("unexpected error for deviceID %d: %v", did, err)
		}

		decoded, err := base64.StdEncoding.DecodeString(string(cert.Certificate))
		if err != nil {
			t.Fatalf("failed to decode for deviceID %d: %v", did, err)
		}

		var sc SenderCertificate
		if err := json.Unmarshal(decoded, &sc); err != nil {
			t.Fatalf("failed to unmarshal for deviceID %d: %v", did, err)
		}

		if sc.SenderDeviceID != did {
			t.Errorf("SenderDeviceID = %d, want %d", sc.SenderDeviceID, did)
		}
	}
}

func TestSignCertificate_WithoutE164(t *testing.T) {
	key := []byte("sign-no-e164-key")
	m := newTestManager(key)

	cert := &SenderCertificate{
		SenderUUID:     "uuid-no-e164",
		SenderDeviceID: 1,
		Expiration:     2000000,
		IdentityKey:    []byte{10, 20, 30},
	}

	sig, err := m.signCertificate(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manually compute expected HMAC.
	payload := struct {
		SenderUUID     string `json:"senderUuid"`
		SenderE164     string `json:"senderE164,omitempty"`
		SenderDeviceID uint32 `json:"senderDeviceId"`
		Expiration     int64  `json:"expiration"`
		IdentityKey    []byte `json:"identityKey"`
	}{
		SenderUUID:     cert.SenderUUID,
		SenderDeviceID: cert.SenderDeviceID,
		Expiration:     cert.Expiration,
		IdentityKey:    cert.IdentityKey,
	}
	data, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)

	if !hmac.Equal(sig, expected) {
		t.Error("signature mismatch for certificate without E164")
	}
}

func TestSignCertificate_SignatureLength(t *testing.T) {
	m := newTestManager([]byte("len-key"))

	cert := &SenderCertificate{
		SenderUUID:     "uuid",
		SenderDeviceID: 1,
		Expiration:     100,
		IdentityKey:    []byte{1},
	}

	sig, err := m.signCertificate(cert)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(sig) != sha256.Size {
		t.Errorf("signature length = %d, want %d", len(sig), sha256.Size)
	}
}

func TestGenerateGroupCredential_DifferentUUIDs(t *testing.T) {
	m := newTestManager([]byte("uuid-diff-key"))

	cred1, err := m.generateGroupCredential("uuid-a", 86400)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cred2, err := m.generateGroupCredential("uuid-b", 86400)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if hmac.Equal(cred1, cred2) {
		t.Error("expected different credentials for different UUIDs")
	}
}

func TestGenerateGroupCredential_VerifyHMAC(t *testing.T) {
	key := []byte("verify-hmac-key")
	m := newTestManager(key)

	cred, err := m.generateGroupCredential("uuid-verify", 172800)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manually compute expected HMAC.
	payload := struct {
		UUID           string `json:"uuid"`
		RedemptionTime int64  `json:"redemptionTime"`
	}{
		UUID:           "uuid-verify",
		RedemptionTime: 172800,
	}
	data, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expected := mac.Sum(nil)

	if !hmac.Equal(cred, expected) {
		t.Error("credential HMAC verification failed")
	}
}

func TestGetGroupCredentials_CredentialsAreInDayOrder(t *testing.T) {
	m := newTestManager([]byte("order-key"))
	ctx := context.Background()

	start := int64(86400)     // day 1
	end := int64(86400*3 + 1) // day 3

	creds, err := m.GetGroupCredentials(ctx, "uuid-order", "pni-order", start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(creds.Credentials) != 3 {
		t.Fatalf("Credentials length = %d, want 3", len(creds.Credentials))
	}

	for i := 0; i < len(creds.Credentials)-1; i++ {
		if creds.Credentials[i].RedemptionTime >= creds.Credentials[i+1].RedemptionTime {
			t.Errorf("credentials not in ascending order: %d >= %d",
				creds.Credentials[i].RedemptionTime, creds.Credentials[i+1].RedemptionTime)
		}
	}
}

func TestGetGroupCredentials_RedemptionTimesAlignToDay(t *testing.T) {
	m := newTestManager([]byte("align-key"))
	ctx := context.Background()

	// Start in the middle of day 1 (some seconds past midnight).
	start := int64(86400 + 43200) // 1.5 days
	end := int64(86400*2 + 43200) // 2.5 days

	creds, err := m.GetGroupCredentials(ctx, "uuid-align", "pni-align", start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, c := range creds.Credentials {
		if c.RedemptionTime%secondsPerDay != 0 {
			t.Errorf("RedemptionTime %d is not aligned to day boundary", c.RedemptionTime)
		}
	}
}

func TestGetGroupCredentials_EqualStartEnd(t *testing.T) {
	m := newTestManager([]byte("equal-key"))
	ctx := context.Background()

	// start == end in the middle of a day.
	ts := int64(86400 + 100)
	creds, err := m.GetGroupCredentials(ctx, "uuid-eq", "pni-eq", ts, ts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(creds.Credentials) != 1 {
		t.Fatalf("Credentials length = %d, want 1", len(creds.Credentials))
	}
}

func TestGetGroupCredentials_NegativeTimestamps(t *testing.T) {
	m := newTestManager([]byte("neg-key"))
	ctx := context.Background()

	_, err := m.GetGroupCredentials(ctx, "uuid-neg", "pni-neg", -200, -100)
	if err != nil {
		t.Fatalf("unexpected error for negative timestamps: %v", err)
	}
}

func TestGetDeliveryCertificate_CertificateIsValidBase64(t *testing.T) {
	m := newTestManager([]byte("b64-key"))
	ctx := context.Background()

	cert, err := m.GetDeliveryCertificate(ctx, "uuid-b64", "+1555", 1, []byte{1}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = base64.StdEncoding.DecodeString(string(cert.Certificate))
	if err != nil {
		t.Errorf("certificate is not valid base64: %v", err)
	}
}

func TestConstants_Values(t *testing.T) {
	if certificateValidityDuration != 24*time.Hour {
		t.Errorf("certificateValidityDuration = %v, want %v", certificateValidityDuration, 24*time.Hour)
	}
	if maxCredentialRangeDays != 7 {
		t.Errorf("maxCredentialRangeDays = %d, want 7", maxCredentialRangeDays)
	}
	if secondsPerDay != 86400 {
		t.Errorf("secondsPerDay = %d, want 86400", secondsPerDay)
	}
}

func TestConstants_Positive(t *testing.T) {
	if certificateValidityDuration <= 0 {
		t.Error("certificateValidityDuration must be positive")
	}
	if maxCredentialRangeDays <= 0 {
		t.Error("maxCredentialRangeDays must be positive")
	}
	if secondsPerDay <= 0 {
		t.Error("secondsPerDay must be positive")
	}
}

func TestSignCertificate_MarshalError(t *testing.T) {
	original := jsonMarshal
	t.Cleanup(func() { jsonMarshal = original })

	jsonMarshal = func(_ any) ([]byte, error) {
		return nil, &marshalError{Message: "simulated"}
	}

	m := newTestManager([]byte("key"))
	cert := &SenderCertificate{
		SenderUUID:     "uuid",
		SenderDeviceID: 1,
		Expiration:     100,
		IdentityKey:    []byte{1},
	}

	_, err := m.signCertificate(cert)
	if err == nil {
		t.Fatal("expected error from signCertificate when marshal fails")
	}

	var target *marshalError
	if !errors.As(err, &target) {
		t.Fatalf("expected *marshalError, got %T: %v", err, err)
	}
}

func TestGenerateGroupCredential_MarshalError(t *testing.T) {
	original := jsonMarshal
	t.Cleanup(func() { jsonMarshal = original })

	jsonMarshal = func(_ any) ([]byte, error) {
		return nil, &marshalError{Message: "simulated"}
	}

	m := newTestManager([]byte("key"))
	_, err := m.generateGroupCredential("uuid", 86400)
	if err == nil {
		t.Fatal("expected error from generateGroupCredential when marshal fails")
	}

	var target *marshalError
	if !errors.As(err, &target) {
		t.Fatalf("expected *marshalError, got %T: %v", err, err)
	}
}

func TestGetDeliveryCertificate_SignMarshalError(t *testing.T) {
	original := jsonMarshal
	t.Cleanup(func() { jsonMarshal = original })

	jsonMarshal = func(_ any) ([]byte, error) {
		return nil, &marshalError{Message: "sign marshal failure"}
	}

	m := newTestManager([]byte("key"))
	ctx := context.Background()

	_, err := m.GetDeliveryCertificate(ctx, "uuid", "+1555", 1, []byte{1}, true)
	if err == nil {
		t.Fatal("expected error when signCertificate marshal fails")
	}

	var target *CertificateGenerationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CertificateGenerationError, got %T: %v", err, err)
	}
	if target.Operation != "sign" {
		t.Errorf("Operation = %q, want %q", target.Operation, "sign")
	}
}

func TestGetDeliveryCertificate_CertMarshalError(t *testing.T) {
	original := jsonMarshal
	t.Cleanup(func() { jsonMarshal = original })

	callCount := 0
	jsonMarshal = func(v any) ([]byte, error) {
		callCount++
		// The first call is from signCertificate (signing payload); let it succeed.
		if callCount == 1 {
			return json.Marshal(v)
		}
		// The second call is from GetDeliveryCertificate (marshaling SenderCertificate); fail it.
		return nil, &marshalError{Message: "cert marshal failure"}
	}

	m := newTestManager([]byte("key"))
	ctx := context.Background()

	_, err := m.GetDeliveryCertificate(ctx, "uuid", "+1555", 1, []byte{1}, true)
	if err == nil {
		t.Fatal("expected error when certificate marshal fails")
	}

	var target *CertificateGenerationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CertificateGenerationError, got %T: %v", err, err)
	}
	if target.Operation != "marshal" {
		t.Errorf("Operation = %q, want %q", target.Operation, "marshal")
	}
}

func TestGetGroupCredentials_CredentialMarshalError(t *testing.T) {
	original := jsonMarshal
	t.Cleanup(func() { jsonMarshal = original })

	jsonMarshal = func(_ any) ([]byte, error) {
		return nil, &marshalError{Message: "credential marshal failure"}
	}

	m := newTestManager([]byte("key"))
	ctx := context.Background()

	_, err := m.GetGroupCredentials(ctx, "uuid", "pni", 86400, 86400)
	if err == nil {
		t.Fatal("expected error when credential marshal fails")
	}

	var target *CertificateGenerationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CertificateGenerationError, got %T: %v", err, err)
	}
	if target.Operation != "group-credential" {
		t.Errorf("Operation = %q, want %q", target.Operation, "group-credential")
	}
}
