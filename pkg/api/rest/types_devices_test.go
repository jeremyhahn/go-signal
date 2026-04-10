package rest

import (
	"testing"
)

func TestLinkDeviceRequestEntity_ToLinkDeviceRequest(t *testing.T) {
	entity := &LinkDeviceRequestEntity{
		VerificationCode: "code-123",
		AccountAttributes: DeviceAccountAttributesEntity{
			FetchesMessages:   true,
			RegistrationId:    111,
			PniRegistrationId: 222,
			Name:              "Linked Device",
			Capabilities:      map[string]bool{"storage": true},
		},
		AciSignedPreKey: SignedPreKeyEntity{
			KeyId:     1,
			PublicKey: testSignedPreKeyPubB64,
			Signature: testSignedPreKeySigB64,
		},
		PniSignedPreKey: SignedPreKeyEntity{
			KeyId:     2,
			PublicKey: testSignedPreKeyPubB64,
			Signature: testSignedPreKeySigB64,
		},
		AciPqLastResortPreKey: KEMSignedPreKeyEntity{
			KeyId:     3,
			PublicKey: testSignedPreKeyPubB64,
			Signature: testSignedPreKeySigB64,
		},
		PniPqLastResortPreKey: KEMSignedPreKeyEntity{
			KeyId:     4,
			PublicKey: testSignedPreKeyPubB64,
			Signature: testSignedPreKeySigB64,
		},
	}

	req := entity.toLinkDeviceRequest()
	if req.VerificationCode != "code-123" {
		t.Errorf("expected verification code 'code-123', got %s", req.VerificationCode)
	}
	if !req.AccountAttributes.FetchesMessages {
		t.Error("expected FetchesMessages true")
	}
	if req.AccountAttributes.RegistrationId != 111 {
		t.Errorf("expected RegistrationId 111, got %d", req.AccountAttributes.RegistrationId)
	}
	if req.AccountAttributes.PniRegistrationId != 222 {
		t.Errorf("expected PniRegistrationId 222, got %d", req.AccountAttributes.PniRegistrationId)
	}
	if req.AccountAttributes.Name != "Linked Device" {
		t.Errorf("expected name 'Linked Device', got %s", req.AccountAttributes.Name)
	}
	if req.AciSignedPreKey.KeyId != 1 {
		t.Errorf("expected AciSignedPreKey KeyId 1, got %d", req.AciSignedPreKey.KeyId)
	}
	if req.PniSignedPreKey.KeyId != 2 {
		t.Errorf("expected PniSignedPreKey KeyId 2, got %d", req.PniSignedPreKey.KeyId)
	}
	if req.AciPqLastResortPreKey.KeyId != 3 {
		t.Errorf("expected AciPqLastResortPreKey KeyId 3, got %d", req.AciPqLastResortPreKey.KeyId)
	}
	if req.PniPqLastResortPreKey.KeyId != 4 {
		t.Errorf("expected PniPqLastResortPreKey KeyId 4, got %d", req.PniPqLastResortPreKey.KeyId)
	}
}

func TestLinkDeviceRequestEntity_ToLinkDeviceRequest_EmptyCapabilities(t *testing.T) {
	entity := &LinkDeviceRequestEntity{
		VerificationCode: "code",
	}

	req := entity.toLinkDeviceRequest()
	if len(req.AccountAttributes.Capabilities) > 0 {
		t.Error("expected empty capabilities for zero value entity")
	}
}
