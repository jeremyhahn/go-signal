package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestHashRegistrationLock_GeneratesSalt(t *testing.T) {
	h, err := HashRegistrationLock("correcthorsebatterystaple")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.Salt == "" {
		t.Fatal("expected non-empty salt")
	}
	salt, err := base64.StdEncoding.DecodeString(h.Salt)
	if err != nil {
		t.Fatalf("salt is not valid base64: %v", err)
	}
	if len(salt) != saltLen {
		t.Fatalf("expected salt length %d, got %d", saltLen, len(salt))
	}
}

func TestHashRegistrationLock_GeneratesHash(t *testing.T) {
	h, err := HashRegistrationLock("correcthorsebatterystaple")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.Hash == "" {
		t.Fatal("expected non-empty hash")
	}
	raw, err := base64.StdEncoding.DecodeString(h.Hash)
	if err != nil {
		t.Fatalf("hash is not valid base64: %v", err)
	}
	if len(raw) != int(argon2KeyLen) {
		t.Fatalf("expected hash length %d, got %d", argon2KeyLen, len(raw))
	}
}

func TestRegistrationLockHash_VerifyCorrectPIN(t *testing.T) {
	pin := "correcthorsebatterystaple"
	h, err := HashRegistrationLock(pin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !h.Verify(pin) {
		t.Error("Verify returned false for correct PIN")
	}
}

func TestRegistrationLockHash_VerifyWrongPIN(t *testing.T) {
	h, err := HashRegistrationLock("correct-pin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h.Verify("wrong-pin") {
		t.Error("Verify returned true for wrong PIN")
	}
}

func TestHashRegistrationLock_DifferentPINsDifferentHashes(t *testing.T) {
	h1, err := HashRegistrationLock("pin-one")
	if err != nil {
		t.Fatalf("unexpected error hashing pin-one: %v", err)
	}
	h2, err := HashRegistrationLock("pin-two")
	if err != nil {
		t.Fatalf("unexpected error hashing pin-two: %v", err)
	}
	if h1.Hash == h2.Hash {
		t.Error("different PINs produced identical hashes")
	}
}

func TestHashRegistrationLock_SamePINDifferentSalts(t *testing.T) {
	pin := "same-pin"
	h1, err := HashRegistrationLock(pin)
	if err != nil {
		t.Fatalf("unexpected error on first hash: %v", err)
	}
	h2, err := HashRegistrationLock(pin)
	if err != nil {
		t.Fatalf("unexpected error on second hash: %v", err)
	}
	if h1.Salt == h2.Salt {
		t.Error("two independent hashes produced identical salts")
	}
	if h1.Hash == h2.Hash {
		t.Error("same PIN with different salts produced identical hashes")
	}
	// Both must still verify correctly.
	if !h1.Verify(pin) {
		t.Error("h1.Verify failed for correct PIN")
	}
	if !h2.Verify(pin) {
		t.Error("h2.Verify failed for correct PIN")
	}
}

func TestRegistrationLockHash_JSONRoundTrip(t *testing.T) {
	pin := "round-trip-pin"
	original, err := HashRegistrationLock(pin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var restored RegistrationLockHash
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if restored.Salt != original.Salt {
		t.Errorf("salt mismatch after round-trip: want %q, got %q", original.Salt, restored.Salt)
	}
	if restored.Hash != original.Hash {
		t.Errorf("hash mismatch after round-trip: want %q, got %q", original.Hash, restored.Hash)
	}
	if !restored.Verify(pin) {
		t.Error("Verify failed after JSON round-trip")
	}
	if restored.Verify("wrong-pin") {
		t.Error("Verify returned true for wrong PIN after round-trip")
	}
}

func TestHashRegistrationLock_EmptyPIN(t *testing.T) {
	h, err := HashRegistrationLock("")
	if err != nil {
		t.Fatalf("unexpected error for empty PIN: %v", err)
	}
	if !h.Verify("") {
		t.Error("Verify returned false for empty PIN that was hashed as empty")
	}
	if h.Verify("non-empty") {
		t.Error("Verify returned true for non-empty PIN against empty-PIN hash")
	}
}

func TestRegistrationLockHash_VerifyCorruptSalt(t *testing.T) {
	h := &RegistrationLockHash{
		Salt: "!!!not-base64!!!",
		Hash: "dGVzdA==",
	}
	if h.Verify("any-pin") {
		t.Error("Verify should return false for corrupt salt")
	}
}

func TestRegistrationLockHash_VerifyCorruptHash(t *testing.T) {
	h, err := HashRegistrationLock("pin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h.Hash = "!!!not-base64!!!"
	if h.Verify("pin") {
		t.Error("Verify should return false for corrupt hash")
	}
}

func TestHashingError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *HashingError
		want string
	}{
		{
			name: "with cause",
			err:  &HashingError{Cause: &mockError{msg: "entropy failure"}},
			want: "registration lock hashing failed: entropy failure",
		},
		{
			name: "without cause",
			err:  &HashingError{},
			want: "registration lock hashing failed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHashingError_Unwrap(t *testing.T) {
	cause := &mockError{msg: "underlying"}
	e := &HashingError{Cause: cause}
	if e.Unwrap() != cause {
		t.Error("Unwrap did not return the wrapped cause")
	}
}

// mockError is a minimal error implementation for tests.
type mockError struct {
	msg string
}

func (m *mockError) Error() string { return m.msg }
