package devices

import (
	"encoding/json"
	"testing"
	"time"
)

func TestProvisioningCode_JSONRoundTrip(t *testing.T) {
	pc := ProvisioningCode{VerificationCode: "abc-123"}

	data, err := json.Marshal(pc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded ProvisioningCode
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.VerificationCode != pc.VerificationCode {
		t.Errorf("VerificationCode = %q, want %q", decoded.VerificationCode, pc.VerificationCode)
	}
}

func TestProvisioningCode_ZeroValue(t *testing.T) {
	var pc ProvisioningCode
	if pc.VerificationCode != "" {
		t.Errorf("expected empty VerificationCode, got %q", pc.VerificationCode)
	}
}

func TestLinkDeviceRequest_JSONRoundTrip(t *testing.T) {
	req := LinkDeviceRequest{
		VerificationCode: "code-1",
		AccountAttributes: DeviceAccountAttributes{
			FetchesMessages:   true,
			RegistrationId:    100,
			PniRegistrationId: 200,
			Name:              "device-name",
			Capabilities:      map[string]bool{"storage": true},
		},
		AciSignedPreKey: SignedPreKeyEntity{
			KeyId:     1,
			PublicKey: "cHVia2V5",
			Signature: "c2lnbmF0dXJl",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded LinkDeviceRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.VerificationCode != "code-1" {
		t.Errorf("VerificationCode = %q, want %q", decoded.VerificationCode, "code-1")
	}
	if decoded.AccountAttributes.Name != "device-name" {
		t.Errorf("Name = %q, want %q", decoded.AccountAttributes.Name, "device-name")
	}
	if !decoded.AccountAttributes.FetchesMessages {
		t.Error("expected FetchesMessages = true")
	}
}

func TestLinkDeviceRequest_ZeroValue(t *testing.T) {
	var req LinkDeviceRequest
	if req.VerificationCode != "" {
		t.Errorf("expected empty VerificationCode, got %q", req.VerificationCode)
	}
	if req.AccountAttributes.Name != "" {
		t.Errorf("expected empty Name, got %q", req.AccountAttributes.Name)
	}
}

func TestDeviceAccountAttributes_JSONTags(t *testing.T) {
	attrs := DeviceAccountAttributes{
		FetchesMessages:   true,
		RegistrationId:    42,
		PniRegistrationId: 43,
		Name:              "test",
		Capabilities:      map[string]bool{"transfer": true, "storage": false},
	}

	data, err := json.Marshal(attrs)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	expectedKeys := []string{"fetchesMessages", "registrationId", "pniRegistrationId", "name", "capabilities"}
	for _, key := range expectedKeys {
		if _, exists := raw[key]; !exists {
			t.Errorf("expected JSON key %q to exist", key)
		}
	}
}

func TestDeviceAccountAttributes_ZeroValue(t *testing.T) {
	var attrs DeviceAccountAttributes
	if attrs.FetchesMessages {
		t.Error("expected FetchesMessages = false")
	}
	if attrs.RegistrationId != 0 {
		t.Errorf("expected zero RegistrationId, got %d", attrs.RegistrationId)
	}
	if attrs.Capabilities != nil {
		t.Errorf("expected nil Capabilities, got %v", attrs.Capabilities)
	}
}

func TestSignedPreKeyEntity_JSONRoundTrip(t *testing.T) {
	entity := SignedPreKeyEntity{
		KeyId:     42,
		PublicKey: "cHVia2V5",
		Signature: "c2lnbmF0dXJl",
	}

	data, err := json.Marshal(entity)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded SignedPreKeyEntity
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.KeyId != 42 {
		t.Errorf("KeyId = %d, want 42", decoded.KeyId)
	}
	if decoded.PublicKey != "cHVia2V5" {
		t.Errorf("PublicKey = %q, want %q", decoded.PublicKey, "cHVia2V5")
	}
}

func TestSignedPreKeyEntity_ZeroValue(t *testing.T) {
	var entity SignedPreKeyEntity
	if entity.KeyId != 0 {
		t.Errorf("expected zero KeyId, got %d", entity.KeyId)
	}
	if entity.PublicKey != "" {
		t.Errorf("expected empty PublicKey, got %q", entity.PublicKey)
	}
}

func TestKEMSignedPreKeyEntity_JSONRoundTrip(t *testing.T) {
	entity := KEMSignedPreKeyEntity{
		KeyId:     99,
		PublicKey: "a2Vta2V5",
		Signature: "a2Vtc2ln",
	}

	data, err := json.Marshal(entity)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded KEMSignedPreKeyEntity
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.KeyId != 99 {
		t.Errorf("KeyId = %d, want 99", decoded.KeyId)
	}
}

func TestKEMSignedPreKeyEntity_ZeroValue(t *testing.T) {
	var entity KEMSignedPreKeyEntity
	if entity.KeyId != 0 {
		t.Errorf("expected zero KeyId, got %d", entity.KeyId)
	}
}

func TestLinkDeviceResponse_JSONRoundTrip(t *testing.T) {
	resp := LinkDeviceResponse{DeviceId: 5}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded LinkDeviceResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.DeviceId != 5 {
		t.Errorf("DeviceId = %d, want 5", decoded.DeviceId)
	}
}

func TestLinkDeviceResponse_ZeroValue(t *testing.T) {
	var resp LinkDeviceResponse
	if resp.DeviceId != 0 {
		t.Errorf("expected zero DeviceId, got %d", resp.DeviceId)
	}
}

func TestProvisioningSession_Fields(t *testing.T) {
	t.Run("all fields populated", func(t *testing.T) {
		now := time.Now()
		session := ProvisioningSession{
			Code:      "test-code",
			UUID:      "test-uuid",
			ExpiresAt: now,
		}

		if session.Code != "test-code" {
			t.Errorf("Code = %q, want %q", session.Code, "test-code")
		}
		if session.UUID != "test-uuid" {
			t.Errorf("UUID = %q, want %q", session.UUID, "test-uuid")
		}
		if !session.ExpiresAt.Equal(now) {
			t.Errorf("ExpiresAt mismatch")
		}
	})

	t.Run("zero value", func(t *testing.T) {
		var session ProvisioningSession
		if session.Code != "" {
			t.Errorf("expected empty Code, got %q", session.Code)
		}
		if session.UUID != "" {
			t.Errorf("expected empty UUID, got %q", session.UUID)
		}
		if !session.ExpiresAt.IsZero() {
			t.Errorf("expected zero ExpiresAt, got %v", session.ExpiresAt)
		}
	})
}
