package keys

import (
	"encoding/json"
	"testing"
)

func TestPreKey_ZeroValue(t *testing.T) {
	var pk PreKey
	if pk.KeyID != 0 {
		t.Errorf("expected zero KeyID, got %d", pk.KeyID)
	}
	if pk.PublicKey != nil {
		t.Errorf("expected nil PublicKey, got %v", pk.PublicKey)
	}
}

func TestPreKey_WithValues(t *testing.T) {
	pk := PreKey{
		KeyID:     42,
		PublicKey: []byte{0x01, 0x02, 0x03},
	}
	if pk.KeyID != 42 {
		t.Errorf("expected KeyID 42, got %d", pk.KeyID)
	}
	if len(pk.PublicKey) != 3 {
		t.Errorf("expected PublicKey length 3, got %d", len(pk.PublicKey))
	}
}

func TestSignedPreKey_ZeroValue(t *testing.T) {
	var spk SignedPreKey
	if spk.KeyID != 0 {
		t.Errorf("expected zero KeyID, got %d", spk.KeyID)
	}
	if spk.PublicKey != nil {
		t.Errorf("expected nil PublicKey, got %v", spk.PublicKey)
	}
	if spk.Signature != nil {
		t.Errorf("expected nil Signature, got %v", spk.Signature)
	}
}

func TestSignedPreKey_WithValues(t *testing.T) {
	spk := SignedPreKey{
		KeyID:     99,
		PublicKey: []byte{0xAA},
		Signature: []byte{0xBB, 0xCC},
	}
	if spk.KeyID != 99 {
		t.Errorf("expected KeyID 99, got %d", spk.KeyID)
	}
	if len(spk.Signature) != 2 {
		t.Errorf("expected Signature length 2, got %d", len(spk.Signature))
	}
}

func TestKEMSignedPreKey_ZeroValue(t *testing.T) {
	var kpk KEMSignedPreKey
	if kpk.KeyID != 0 {
		t.Errorf("expected zero KeyID, got %d", kpk.KeyID)
	}
	if kpk.PublicKey != nil {
		t.Errorf("expected nil PublicKey, got %v", kpk.PublicKey)
	}
	if kpk.Signature != nil {
		t.Errorf("expected nil Signature, got %v", kpk.Signature)
	}
}

func TestKEMSignedPreKey_WithValues(t *testing.T) {
	kpk := KEMSignedPreKey{
		KeyID:     1000,
		PublicKey: []byte{0x10, 0x20},
		Signature: []byte{0x30},
	}
	if kpk.KeyID != 1000 {
		t.Errorf("expected KeyID 1000, got %d", kpk.KeyID)
	}
	if len(kpk.PublicKey) != 2 {
		t.Errorf("expected PublicKey length 2, got %d", len(kpk.PublicKey))
	}
}

func TestPreKeyBundle_ZeroValue(t *testing.T) {
	var b PreKeyBundle
	if b.IdentityKey != nil {
		t.Errorf("expected nil IdentityKey, got %v", b.IdentityKey)
	}
	if b.PreKey != nil {
		t.Errorf("expected nil PreKey, got %v", b.PreKey)
	}
	if b.SignedPreKey != nil {
		t.Errorf("expected nil SignedPreKey, got %v", b.SignedPreKey)
	}
	if b.KEMPreKey != nil {
		t.Errorf("expected nil KEMPreKey, got %v", b.KEMPreKey)
	}
}

func TestPreKeyBundle_FullyPopulated(t *testing.T) {
	b := PreKeyBundle{
		IdentityKey:  []byte{0xFF},
		PreKey:       &PreKey{KeyID: 1, PublicKey: []byte{0x01}},
		SignedPreKey: &SignedPreKey{KeyID: 2, PublicKey: []byte{0x02}, Signature: []byte{0x03}},
		KEMPreKey:    &KEMSignedPreKey{KeyID: 3, PublicKey: []byte{0x04}, Signature: []byte{0x05}},
	}
	if b.PreKey.KeyID != 1 {
		t.Errorf("expected PreKey.KeyID 1, got %d", b.PreKey.KeyID)
	}
	if b.SignedPreKey.KeyID != 2 {
		t.Errorf("expected SignedPreKey.KeyID 2, got %d", b.SignedPreKey.KeyID)
	}
	if b.KEMPreKey.KeyID != 3 {
		t.Errorf("expected KEMPreKey.KeyID 3, got %d", b.KEMPreKey.KeyID)
	}
}

func TestPreKeyState_ZeroValue(t *testing.T) {
	var s PreKeyState
	if s.ECCount != 0 {
		t.Errorf("expected zero ECCount, got %d", s.ECCount)
	}
	if s.KEMCount != 0 {
		t.Errorf("expected zero KEMCount, got %d", s.KEMCount)
	}
}

func TestPreKeyState_WithValues(t *testing.T) {
	s := PreKeyState{ECCount: 50, KEMCount: 100}
	if s.ECCount != 50 {
		t.Errorf("expected ECCount 50, got %d", s.ECCount)
	}
	if s.KEMCount != 100 {
		t.Errorf("expected KEMCount 100, got %d", s.KEMCount)
	}
}

func TestPreKeyResponse_JSONRoundTrip(t *testing.T) {
	resp := PreKeyResponse{
		IdentityKey: []byte{0x01, 0x02},
		Devices: []PreKeyResponseItem{
			{
				DeviceID:       1,
				RegistrationID: 12345,
				SignedPreKey:   &SignedPreKey{KeyID: 10, PublicKey: []byte{0xAA}, Signature: []byte{0xBB}},
				PreKey:         &PreKey{KeyID: 20, PublicKey: []byte{0xCC}},
				KEMPreKey:      &KEMSignedPreKey{KeyID: 30, PublicKey: []byte{0xDD}, Signature: []byte{0xEE}},
			},
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded PreKeyResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(decoded.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(decoded.Devices))
	}
	if decoded.Devices[0].DeviceID != 1 {
		t.Errorf("expected DeviceID 1, got %d", decoded.Devices[0].DeviceID)
	}
	if decoded.Devices[0].RegistrationID != 12345 {
		t.Errorf("expected RegistrationID 12345, got %d", decoded.Devices[0].RegistrationID)
	}
}

func TestPreKeyResponse_EmptyDevices(t *testing.T) {
	resp := PreKeyResponse{
		IdentityKey: []byte{0x01},
		Devices:     []PreKeyResponseItem{},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded PreKeyResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(decoded.Devices) != 0 {
		t.Errorf("expected 0 devices, got %d", len(decoded.Devices))
	}
}

func TestPreKeyResponseItem_OmitsEmptyOptionalFields(t *testing.T) {
	item := PreKeyResponseItem{
		DeviceID:       1,
		RegistrationID: 100,
		SignedPreKey:   &SignedPreKey{KeyID: 5, PublicKey: []byte{0x01}, Signature: []byte{0x02}},
	}
	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}
	if _, ok := m["preKey"]; ok {
		t.Error("expected preKey to be omitted when nil")
	}
	if _, ok := m["pqPreKey"]; ok {
		t.Error("expected pqPreKey to be omitted when nil")
	}
}

func TestPreKeyResponseItem_IncludesOptionalFields(t *testing.T) {
	item := PreKeyResponseItem{
		DeviceID:       2,
		RegistrationID: 200,
		SignedPreKey:   &SignedPreKey{KeyID: 5, PublicKey: []byte{0x01}, Signature: []byte{0x02}},
		PreKey:         &PreKey{KeyID: 10, PublicKey: []byte{0x03}},
		KEMPreKey:      &KEMSignedPreKey{KeyID: 15, PublicKey: []byte{0x04}, Signature: []byte{0x05}},
	}
	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}
	if _, ok := m["preKey"]; !ok {
		t.Error("expected preKey to be present")
	}
	if _, ok := m["pqPreKey"]; !ok {
		t.Error("expected pqPreKey to be present")
	}
}

func TestSetKeysRequest_ZeroValue(t *testing.T) {
	var req SetKeysRequest
	if req.PreKeys != nil {
		t.Errorf("expected nil PreKeys, got %v", req.PreKeys)
	}
	if req.SignedPreKey != nil {
		t.Errorf("expected nil SignedPreKey, got %v", req.SignedPreKey)
	}
	if req.KEMPreKeys != nil {
		t.Errorf("expected nil KEMPreKeys, got %v", req.KEMPreKeys)
	}
}

func TestSetKeysRequest_JSONRoundTrip(t *testing.T) {
	req := SetKeysRequest{
		PreKeys:      []*PreKey{{KeyID: 1, PublicKey: []byte{0x01}}},
		SignedPreKey: &SignedPreKey{KeyID: 2, PublicKey: []byte{0x02}, Signature: []byte{0x03}},
		KEMPreKeys:   []*KEMSignedPreKey{{KeyID: 3, PublicKey: []byte{0x04}, Signature: []byte{0x05}}},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded SetKeysRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(decoded.PreKeys) != 1 {
		t.Errorf("expected 1 PreKey, got %d", len(decoded.PreKeys))
	}
	if decoded.SignedPreKey == nil {
		t.Error("expected non-nil SignedPreKey")
	}
	if len(decoded.KEMPreKeys) != 1 {
		t.Errorf("expected 1 KEMPreKey, got %d", len(decoded.KEMPreKeys))
	}
}

func TestSendKeysResponse_ZeroValue(t *testing.T) {
	var resp SendKeysResponse
	_ = resp // placeholder struct, verify it compiles
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded SendKeysResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
}

func TestSendKeysResponse_JSONRoundTrip(t *testing.T) {
	resp := SendKeysResponse{}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if string(data) != "{}" {
		t.Errorf("expected empty JSON object, got %s", string(data))
	}
}
