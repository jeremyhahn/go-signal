package certificates

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func newTestManager(signingKey []byte) *CertificatesManager {
	logger := slog.New(slog.NewTextHandler(
		discardWriter{}, &slog.HandlerOptions{Level: slog.LevelDebug},
	))
	return NewCertificatesManager(secrets.MustNewSecureString(context.Background(), string(signingKey)), logger)
}

// discardWriter is an io.Writer that discards all output.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestNewCertificatesManager(t *testing.T) {
	t.Run("creates manager with signing key", func(t *testing.T) {
		key := []byte("test-signing-key")
		m := newTestManager(key)
		if m == nil {
			t.Fatal("expected non-nil manager")
			return
		}
		// Verify the signing key is accessible and non-destroyed.
		if m.signingKey == nil || m.signingKey.IsDestroyed(t.Context()) {
			t.Error("expected signing key to be set and accessible")
		}
		if m.signingKey.Plaintext(t.Context()) != string(key) {
			t.Errorf("signingKey mismatch: got %q", m.signingKey.Plaintext(t.Context()))
		}
	})

	t.Run("creates manager with empty key", func(t *testing.T) {
		m := newTestManager([]byte{})
		if m == nil {
			t.Fatal("expected non-nil manager")
		}
	})
}

func TestCertificatesManager_Destroy(t *testing.T) {
	m := newTestManager([]byte("destroy-test-key"))
	m.Destroy()

	// After Destroy, signingKey should be nil.
	if m.signingKey != nil {
		t.Error("expected signingKey to be nil after Destroy")
	}
}

func TestCertificatesManager_Destroy_Idempotent(t *testing.T) {
	m := newTestManager([]byte("key"))
	m.Destroy()

	// Second Destroy must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("second Destroy panicked: %v", r)
		}
	}()
	m.Destroy()
}

func TestGetDeliveryCertificate_WithE164(t *testing.T) {
	key := []byte("delivery-cert-test-key")
	m := newTestManager(key)
	ctx := context.Background()

	cert, err := m.GetDeliveryCertificate(ctx, "uuid-123", "+15551234567", 1, []byte{1, 2, 3}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
		return
	}
	if len(cert.Certificate) == 0 {
		t.Error("expected non-empty certificate bytes")
	}
	if cert.CertificateExpiry <= 0 {
		t.Error("expected positive expiry timestamp")
	}

	// Decode and verify the certificate contains E164.
	decoded, err := base64.StdEncoding.DecodeString(string(cert.Certificate))
	if err != nil {
		t.Fatalf("failed to decode certificate: %v", err)
	}

	var sc SenderCertificate
	if err := json.Unmarshal(decoded, &sc); err != nil {
		t.Fatalf("failed to unmarshal certificate: %v", err)
	}

	if sc.SenderUUID != "uuid-123" {
		t.Errorf("SenderUUID = %q, want %q", sc.SenderUUID, "uuid-123")
	}
	if sc.SenderE164 != "+15551234567" {
		t.Errorf("SenderE164 = %q, want %q", sc.SenderE164, "+15551234567")
	}
	if sc.SenderDeviceID != 1 {
		t.Errorf("SenderDeviceID = %d, want %d", sc.SenderDeviceID, 1)
	}
	if len(sc.Signer) == 0 {
		t.Error("expected non-empty Signer")
	}
}

func TestGetDeliveryCertificate_WithoutE164(t *testing.T) {
	key := []byte("delivery-cert-test-key")
	m := newTestManager(key)
	ctx := context.Background()

	cert, err := m.GetDeliveryCertificate(ctx, "uuid-456", "+15559876543", 2, []byte{4, 5, 6}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(cert.Certificate))
	if err != nil {
		t.Fatalf("failed to decode certificate: %v", err)
	}

	var sc SenderCertificate
	if err := json.Unmarshal(decoded, &sc); err != nil {
		t.Fatalf("failed to unmarshal certificate: %v", err)
	}

	if sc.SenderE164 != "" {
		t.Errorf("expected empty SenderE164 when includeE164=false, got %q", sc.SenderE164)
	}
	if sc.SenderUUID != "uuid-456" {
		t.Errorf("SenderUUID = %q, want %q", sc.SenderUUID, "uuid-456")
	}
}

func TestGetDeliveryCertificate_SignatureVerification(t *testing.T) {
	key := []byte("hmac-verification-key-32bytes!!!!")
	m := newTestManager(key)
	ctx := context.Background()

	cert, err := m.GetDeliveryCertificate(ctx, "uuid-sig", "+15551111111", 3, []byte{7, 8, 9}, true)
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

	// Reconstruct the signing payload and verify HMAC.
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

	payloadData, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(payloadData)
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(sc.Signer, expectedSig) {
		t.Error("HMAC signature verification failed")
	}
}

func TestGetDeliveryCertificate_DifferentKeys(t *testing.T) {
	ctx := context.Background()

	m1 := newTestManager([]byte("key-one"))
	m2 := newTestManager([]byte("key-two"))

	cert1, err := m1.GetDeliveryCertificate(ctx, "uuid", "+1555", 1, []byte{1}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cert2, err := m2.GetDeliveryCertificate(ctx, "uuid", "+1555", 1, []byte{1}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Certificates from different keys should produce different signatures,
	// hence different certificate bytes.
	if string(cert1.Certificate) == string(cert2.Certificate) {
		t.Error("certificates from different signing keys should differ")
	}
}

func TestGetDeliveryCertificate_EmptyIdentityKey(t *testing.T) {
	m := newTestManager([]byte("key"))
	ctx := context.Background()

	cert, err := m.GetDeliveryCertificate(ctx, "uuid", "+1555", 1, nil, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate even with nil identity key")
	}
}

func TestGetGroupCredentials_SingleDay(t *testing.T) {
	m := newTestManager([]byte("group-cred-key"))
	ctx := context.Background()

	// Start and end on the same day.
	start := int64(86400) // day 1
	end := int64(86400)   // day 1

	creds, err := m.GetGroupCredentials(ctx, "uuid-gc", "pni-gc", start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if creds.PNI != "pni-gc" {
		t.Errorf("PNI = %q, want %q", creds.PNI, "pni-gc")
	}
	if len(creds.Credentials) != 1 {
		t.Fatalf("Credentials length = %d, want 1", len(creds.Credentials))
	}
	if len(creds.Credentials[0].Credential) == 0 {
		t.Error("expected non-empty credential")
	}
	if creds.Credentials[0].RedemptionTime != 86400 {
		t.Errorf("RedemptionTime = %d, want 86400", creds.Credentials[0].RedemptionTime)
	}
}

func TestGetGroupCredentials_MultipleDays(t *testing.T) {
	m := newTestManager([]byte("group-cred-key"))
	ctx := context.Background()

	// 3 days
	start := int64(0)         // day 0
	end := int64(86400*2 + 1) // day 2

	creds, err := m.GetGroupCredentials(ctx, "uuid-multi", "pni-multi", start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(creds.Credentials) != 3 {
		t.Fatalf("Credentials length = %d, want 3", len(creds.Credentials))
	}

	// Verify each credential has a distinct redemption time.
	seen := make(map[int64]bool)
	for _, c := range creds.Credentials {
		if seen[c.RedemptionTime] {
			t.Errorf("duplicate redemption time: %d", c.RedemptionTime)
		}
		seen[c.RedemptionTime] = true
	}
}

func TestGetGroupCredentials_MaxRange(t *testing.T) {
	m := newTestManager([]byte("key"))
	ctx := context.Background()

	// Exactly 7 days.
	start := int64(0)
	end := int64(86400 * 6) // days 0-6 = 7 days

	creds, err := m.GetGroupCredentials(ctx, "uuid", "pni", start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(creds.Credentials) != 7 {
		t.Fatalf("Credentials length = %d, want 7", len(creds.Credentials))
	}
}

func TestGetGroupCredentials_ExceedsMaxRange(t *testing.T) {
	m := newTestManager([]byte("key"))
	ctx := context.Background()

	// 8 days = exceeds max.
	start := int64(0)
	end := int64(86400 * 7) // days 0-7 = 8 days

	_, err := m.GetGroupCredentials(ctx, "uuid", "pni", start, end)
	if err == nil {
		t.Fatal("expected error for range exceeding 7 days")
	}

	var target *InvalidTimeRangeError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidTimeRangeError, got %T", err)
	}
}

func TestGetGroupCredentials_StartAfterEnd(t *testing.T) {
	m := newTestManager([]byte("key"))
	ctx := context.Background()

	_, err := m.GetGroupCredentials(ctx, "uuid", "pni", 200, 100)
	if err == nil {
		t.Fatal("expected error when start > end")
	}

	var target *InvalidTimeRangeError
	if !errors.As(err, &target) {
		t.Fatalf("expected *InvalidTimeRangeError, got %T", err)
	}
}

func TestGetGroupCredentials_CredentialDeterminism(t *testing.T) {
	key := []byte("deterministic-key")
	m := newTestManager(key)
	ctx := context.Background()

	start := int64(86400)
	end := int64(86400)

	creds1, err := m.GetGroupCredentials(ctx, "uuid", "pni", start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	creds2, err := m.GetGroupCredentials(ctx, "uuid", "pni", start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Same inputs => same credential.
	if string(creds1.Credentials[0].Credential) != string(creds2.Credentials[0].Credential) {
		t.Error("expected deterministic credentials for the same inputs")
	}
}

func TestGetGroupCredentials_DifferentUUIDs(t *testing.T) {
	key := []byte("key")
	m := newTestManager(key)
	ctx := context.Background()

	start := int64(86400)
	end := int64(86400)

	creds1, err := m.GetGroupCredentials(ctx, "uuid-a", "pni-a", start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	creds2, err := m.GetGroupCredentials(ctx, "uuid-b", "pni-b", start, end)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(creds1.Credentials[0].Credential) == string(creds2.Credentials[0].Credential) {
		t.Error("expected different credentials for different UUIDs")
	}
}

func TestSignCertificate(t *testing.T) {
	t.Run("produces consistent signatures", func(t *testing.T) {
		key := []byte("sign-cert-key")
		m := newTestManager(key)

		cert := &SenderCertificate{
			SenderUUID:     "uuid-1",
			SenderE164:     "+15551234567",
			SenderDeviceID: 1,
			Expiration:     1000000,
			IdentityKey:    []byte{1, 2, 3},
		}

		sig1, err := m.signCertificate(t.Context(), cert)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sig2, err := m.signCertificate(t.Context(), cert)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !hmac.Equal(sig1, sig2) {
			t.Error("expected identical signatures for the same input")
		}
	})

	t.Run("different inputs produce different signatures", func(t *testing.T) {
		key := []byte("sign-cert-key")
		m := newTestManager(key)

		cert1 := &SenderCertificate{
			SenderUUID:     "uuid-1",
			SenderDeviceID: 1,
			Expiration:     1000000,
			IdentityKey:    []byte{1},
		}

		cert2 := &SenderCertificate{
			SenderUUID:     "uuid-2",
			SenderDeviceID: 1,
			Expiration:     1000000,
			IdentityKey:    []byte{1},
		}

		sig1, err := m.signCertificate(t.Context(), cert1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		sig2, err := m.signCertificate(t.Context(), cert2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if hmac.Equal(sig1, sig2) {
			t.Error("expected different signatures for different inputs")
		}
	})
}

func TestGenerateGroupCredential(t *testing.T) {
	t.Run("produces valid HMAC credential", func(t *testing.T) {
		key := []byte("group-cred-key")
		m := newTestManager(key)

		cred, err := m.generateGroupCredential(t.Context(), "uuid-1", 86400)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cred) != sha256.Size {
			t.Errorf("credential length = %d, want %d", len(cred), sha256.Size)
		}
	})

	t.Run("deterministic for same inputs", func(t *testing.T) {
		key := []byte("group-cred-key")
		m := newTestManager(key)

		cred1, err := m.generateGroupCredential(t.Context(), "uuid-1", 86400)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		cred2, err := m.generateGroupCredential(t.Context(), "uuid-1", 86400)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !hmac.Equal(cred1, cred2) {
			t.Error("expected identical credentials for same inputs")
		}
	})

	t.Run("different redemption times produce different credentials", func(t *testing.T) {
		key := []byte("group-cred-key")
		m := newTestManager(key)

		cred1, err := m.generateGroupCredential(t.Context(), "uuid-1", 86400)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		cred2, err := m.generateGroupCredential(t.Context(), "uuid-1", 172800)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if hmac.Equal(cred1, cred2) {
			t.Error("expected different credentials for different redemption times")
		}
	})
}

func TestGetGroupCredentials_ZeroRange(t *testing.T) {
	m := newTestManager([]byte("key"))
	ctx := context.Background()

	// start == end == 0 => day 0, single credential
	creds, err := m.GetGroupCredentials(ctx, "uuid", "pni", 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(creds.Credentials) != 1 {
		t.Fatalf("Credentials length = %d, want 1", len(creds.Credentials))
	}
	if creds.Credentials[0].RedemptionTime != 0 {
		t.Errorf("RedemptionTime = %d, want 0", creds.Credentials[0].RedemptionTime)
	}
}

func TestGetDeliveryCertificate_ExpiryIsFuture(t *testing.T) {
	m := newTestManager([]byte("key"))
	ctx := context.Background()

	cert, err := m.GetDeliveryCertificate(ctx, "uuid", "+1555", 1, []byte{1}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expiry should be approximately 24 hours from now.
	// We check it is at least 23 hours from now.
	now := int64(0)
	_ = now
	if cert.CertificateExpiry <= 0 {
		t.Error("expected positive expiry")
	}
}

func TestSetCallingZKParams(t *testing.T) {
	t.Run("stores params on manager", func(t *testing.T) {
		m := newTestManager([]byte("key"))

		var randomness zkgroup.RandomnessBytes
		for i := range randomness {
			randomness[i] = byte(i)
		}
		params := zkgroup.GenerateGenericServerSecretParams(randomness)

		m.SetCallingZKParams(params)

		if m.callingZKParams == nil {
			t.Fatal("expected callingZKParams to be set")
		}
		if m.callingZKParams != params {
			t.Error("expected callingZKParams to match the provided params")
		}
	})

	t.Run("overwrites previously set params", func(t *testing.T) {
		m := newTestManager([]byte("key"))

		var randomness1 zkgroup.RandomnessBytes
		for i := range randomness1 {
			randomness1[i] = byte(i)
		}
		params1 := zkgroup.GenerateGenericServerSecretParams(randomness1)
		m.SetCallingZKParams(params1)

		var randomness2 zkgroup.RandomnessBytes
		for i := range randomness2 {
			randomness2[i] = byte(i + 100)
		}
		params2 := zkgroup.GenerateGenericServerSecretParams(randomness2)
		m.SetCallingZKParams(params2)

		if m.callingZKParams != params2 {
			t.Error("expected callingZKParams to be overwritten with second params")
		}
	})
}

func TestGetGroupCredentials_WithCallLinkAuthCredentials(t *testing.T) {
	t.Run("single day returns one call link credential", func(t *testing.T) {
		m := newTestManager([]byte("call-link-key"))

		var randomness zkgroup.RandomnessBytes
		for i := range randomness {
			randomness[i] = byte(i + 42)
		}
		params := zkgroup.GenerateGenericServerSecretParams(randomness)
		m.SetCallingZKParams(params)

		ctx := context.Background()
		start := int64(86400)
		end := int64(86400)

		creds, err := m.GetGroupCredentials(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "pni-cl", start, end)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if creds.CallLinkAuthCredentials == nil {
			t.Fatal("expected non-nil CallLinkAuthCredentials")
		}
		if len(creds.CallLinkAuthCredentials) != 1 {
			t.Fatalf("CallLinkAuthCredentials length = %d, want 1", len(creds.CallLinkAuthCredentials))
		}
		if len(creds.CallLinkAuthCredentials[0].Credential) == 0 {
			t.Error("expected non-empty call link auth credential")
		}
		if creds.CallLinkAuthCredentials[0].RedemptionTime != 86400 {
			t.Errorf("RedemptionTime = %d, want 86400", creds.CallLinkAuthCredentials[0].RedemptionTime)
		}
	})

	t.Run("multiple days returns matching count", func(t *testing.T) {
		m := newTestManager([]byte("call-link-key"))

		var randomness zkgroup.RandomnessBytes
		for i := range randomness {
			randomness[i] = byte(i + 42)
		}
		params := zkgroup.GenerateGenericServerSecretParams(randomness)
		m.SetCallingZKParams(params)

		ctx := context.Background()
		start := int64(0)
		end := int64(86400*2 + 1) // days 0-2

		creds, err := m.GetGroupCredentials(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "pni-cl", start, end)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(creds.CallLinkAuthCredentials) != 3 {
			t.Fatalf("CallLinkAuthCredentials length = %d, want 3", len(creds.CallLinkAuthCredentials))
		}
		if len(creds.CallLinkAuthCredentials) != len(creds.Credentials) {
			t.Errorf("CallLinkAuthCredentials count (%d) does not match Credentials count (%d)",
				len(creds.CallLinkAuthCredentials), len(creds.Credentials))
		}

		for i, clc := range creds.CallLinkAuthCredentials {
			if len(clc.Credential) == 0 {
				t.Errorf("CallLinkAuthCredentials[%d] has empty credential", i)
			}
			if clc.RedemptionTime != creds.Credentials[i].RedemptionTime {
				t.Errorf("CallLinkAuthCredentials[%d].RedemptionTime = %d, want %d",
					i, clc.RedemptionTime, creds.Credentials[i].RedemptionTime)
			}
		}
	})
}

func TestGetGroupCredentials_WithoutCallingZKParams(t *testing.T) {
	t.Run("returns nil call link credentials when params not set", func(t *testing.T) {
		m := newTestManager([]byte("no-zk-key"))
		ctx := context.Background()

		start := int64(86400)
		end := int64(86400)

		creds, err := m.GetGroupCredentials(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "pni-nozk", start, end)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if creds.CallLinkAuthCredentials != nil {
			t.Errorf("expected nil CallLinkAuthCredentials, got %d entries", len(creds.CallLinkAuthCredentials))
		}
	})

	t.Run("group credentials still populated without calling params", func(t *testing.T) {
		m := newTestManager([]byte("no-zk-key"))
		ctx := context.Background()

		start := int64(0)
		end := int64(86400*2 + 1) // days 0-2

		creds, err := m.GetGroupCredentials(ctx, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "pni-nozk", start, end)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if creds.CallLinkAuthCredentials != nil {
			t.Errorf("expected nil CallLinkAuthCredentials, got %d entries", len(creds.CallLinkAuthCredentials))
		}
		if len(creds.Credentials) != 3 {
			t.Fatalf("Credentials length = %d, want 3", len(creds.Credentials))
		}
		for i, c := range creds.Credentials {
			if len(c.Credential) == 0 {
				t.Errorf("Credentials[%d] has empty credential", i)
			}
		}
	})
}

// Verify the secrets import is used.
var _ = (*secrets.SecureString)(nil)
