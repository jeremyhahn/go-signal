package auth

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"
)

func testGroupSendKey() []byte {
	return []byte("test-group-send-secret-key-32by")
}

func TestGenerateGroupSendToken_NotNil(t *testing.T) {
	token := GenerateGroupSendToken(testGroupSendKey(), "sender-uuid", "group-id", time.Hour)
	if token == nil {
		t.Fatal("expected non-nil token")
	}
}

func TestGenerateGroupSendToken_Fields(t *testing.T) {
	token := GenerateGroupSendToken(testGroupSendKey(), "sender-uuid", "group-id", time.Hour)
	if token.Expiration <= 0 {
		t.Error("expected positive expiration")
	}
	if len(token.HMAC) != sha256.Size {
		t.Errorf("HMAC size: got %d, want %d", len(token.HMAC), sha256.Size)
	}
}

func TestGenerateGroupSendToken_DefaultTTL(t *testing.T) {
	before := time.Now().Unix()
	token := GenerateGroupSendToken(testGroupSendKey(), "sender", "group", 0)
	after := time.Now().Unix()

	expectedMin := before + int64(DefaultGroupSendTokenTTL.Seconds())
	expectedMax := after + int64(DefaultGroupSendTokenTTL.Seconds())

	if token.Expiration < expectedMin || token.Expiration > expectedMax {
		t.Errorf("expiration %d not within expected range [%d, %d]", token.Expiration, expectedMin, expectedMax)
	}
}

func TestVerifyGroupSendToken_Valid(t *testing.T) {
	key := testGroupSendKey()
	token := GenerateGroupSendToken(key, "sender-uuid", "group-id", time.Hour)

	if !VerifyGroupSendToken(key, token, "sender-uuid", "group-id") {
		t.Fatal("expected valid token to verify successfully")
	}
}

func TestVerifyGroupSendToken_WrongSender(t *testing.T) {
	key := testGroupSendKey()
	token := GenerateGroupSendToken(key, "sender-uuid", "group-id", time.Hour)

	if VerifyGroupSendToken(key, token, "wrong-sender", "group-id") {
		t.Fatal("expected verification to fail with wrong sender")
	}
}

func TestVerifyGroupSendToken_WrongGroup(t *testing.T) {
	key := testGroupSendKey()
	token := GenerateGroupSendToken(key, "sender-uuid", "group-id", time.Hour)

	if VerifyGroupSendToken(key, token, "sender-uuid", "wrong-group") {
		t.Fatal("expected verification to fail with wrong group")
	}
}

func TestVerifyGroupSendToken_WrongKey(t *testing.T) {
	key := testGroupSendKey()
	token := GenerateGroupSendToken(key, "sender-uuid", "group-id", time.Hour)

	wrongKey := []byte("wrong-key-different-secret-key!")
	if VerifyGroupSendToken(wrongKey, token, "sender-uuid", "group-id") {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestVerifyGroupSendToken_Expired(t *testing.T) {
	key := testGroupSendKey()
	token := GenerateGroupSendToken(key, "sender-uuid", "group-id", time.Hour)
	// Force expiration to the past.
	token.Expiration = time.Now().Unix() - 1

	if VerifyGroupSendToken(key, token, "sender-uuid", "group-id") {
		t.Fatal("expected verification to fail for expired token")
	}
}

func TestVerifyGroupSendToken_NilToken(t *testing.T) {
	if VerifyGroupSendToken(testGroupSendKey(), nil, "sender", "group") {
		t.Fatal("expected verification to fail for nil token")
	}
}

func TestVerifyGroupSendToken_ShortHMAC(t *testing.T) {
	token := &GroupSendToken{
		Expiration: time.Now().Unix() + 3600,
		HMAC:       []byte{1, 2, 3},
	}
	if VerifyGroupSendToken(testGroupSendKey(), token, "sender", "group") {
		t.Fatal("expected verification to fail for short HMAC")
	}
}

func TestSerializeGroupSendToken(t *testing.T) {
	key := testGroupSendKey()
	token := GenerateGroupSendToken(key, "sender", "group", time.Hour)

	data := SerializeGroupSendToken(token)
	if len(data) != groupSendTokenSize {
		t.Fatalf("serialized size: got %d, want %d", len(data), groupSendTokenSize)
	}
}

func TestSerializeGroupSendToken_NilToken(t *testing.T) {
	data := SerializeGroupSendToken(nil)
	if data != nil {
		t.Fatal("expected nil for nil token")
	}
}

func TestDeserializeGroupSendToken(t *testing.T) {
	key := testGroupSendKey()
	original := GenerateGroupSendToken(key, "sender", "group", time.Hour)

	data := SerializeGroupSendToken(original)
	restored := DeserializeGroupSendToken(data)

	if restored == nil {
		t.Fatal("expected non-nil restored token")
	}
	if restored.Expiration != original.Expiration {
		t.Errorf("expiration: got %d, want %d", restored.Expiration, original.Expiration)
	}
	if !bytes.Equal(restored.HMAC, original.HMAC) {
		t.Error("HMAC mismatch after round-trip")
	}
}

func TestDeserializeGroupSendToken_WrongSize(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	if DeserializeGroupSendToken(data) != nil {
		t.Fatal("expected nil for wrong-size data")
	}
}

func TestDeserializeGroupSendToken_EmptySlice(t *testing.T) {
	if DeserializeGroupSendToken([]byte{}) != nil {
		t.Fatal("expected nil for empty slice")
	}
}

func TestGroupSendToken_RoundTrip(t *testing.T) {
	key := testGroupSendKey()
	token := GenerateGroupSendToken(key, "sender-uuid", "group-id", 2*time.Hour)

	data := SerializeGroupSendToken(token)
	restored := DeserializeGroupSendToken(data)

	if !VerifyGroupSendToken(key, restored, "sender-uuid", "group-id") {
		t.Fatal("restored token should verify successfully")
	}
}

func TestGroupSendToken_TamperedData(t *testing.T) {
	key := testGroupSendKey()
	token := GenerateGroupSendToken(key, "sender-uuid", "group-id", time.Hour)

	data := SerializeGroupSendToken(token)
	// Tamper with the HMAC.
	data[10] ^= 0xFF

	restored := DeserializeGroupSendToken(data)
	if VerifyGroupSendToken(key, restored, "sender-uuid", "group-id") {
		t.Fatal("tampered token should not verify")
	}
}
