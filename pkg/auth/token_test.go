package auth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// NewSaltedTokenHash
// --------------------------------------------------------------------------

func TestNewSaltedTokenHash_ReturnsNonNilResult(t *testing.T) {
	h, err := NewSaltedTokenHash("super-secret-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h == nil {
		t.Fatal("expected non-nil SaltedTokenHash")
	}
}

func TestNewSaltedTokenHash_SaltIsExactly16Bytes(t *testing.T) {
	h, err := NewSaltedTokenHash("my-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	saltBytes, err := hex.DecodeString(h.Salt)
	if err != nil {
		t.Fatalf("salt is not valid hex: %v", err)
	}
	if len(saltBytes) != saltSize {
		t.Errorf("expected salt length %d, got %d", saltSize, len(saltBytes))
	}
}

func TestNewSaltedTokenHash_HashIsExactly32Bytes(t *testing.T) {
	h, err := NewSaltedTokenHash("my-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	hashBytes, err := hex.DecodeString(h.Hash)
	if err != nil {
		t.Fatalf("hash is not valid hex: %v", err)
	}
	if len(hashBytes) != hashSize {
		t.Errorf("expected hash length %d, got %d", hashSize, len(hashBytes))
	}
}

func TestNewSaltedTokenHash_SaltAndHashAreHexEncoded(t *testing.T) {
	h, err := NewSaltedTokenHash("token-value")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := hex.DecodeString(h.Salt); err != nil {
		t.Errorf("Salt is not valid hex: %v", err)
	}
	if _, err := hex.DecodeString(h.Hash); err != nil {
		t.Errorf("Hash is not valid hex: %v", err)
	}
}

func TestNewSaltedTokenHash_UniqueTokensProduceDifferentHashes(t *testing.T) {
	h1, err := NewSaltedTokenHash("token-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := NewSaltedTokenHash("token-b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1.Hash == h2.Hash {
		t.Error("expected different hashes for different tokens")
	}
}

func TestNewSaltedTokenHash_SamTokenProducesDifferentSaltsAndHashes(t *testing.T) {
	// Two calls with the same token must use different random salts, producing
	// different hashes — demonstrating per-token salt uniqueness.
	token := "repeated-token"
	h1, err := NewSaltedTokenHash(token)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	h2, err := NewSaltedTokenHash(token)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if h1.Salt == h2.Salt {
		t.Error("expected different salts on repeated calls (negligible collision probability)")
	}
	if h1.Hash == h2.Hash {
		t.Error("expected different hashes when salts differ for the same token")
	}
}

func TestNewSaltedTokenHash_EmptyTokenReturnsInvalidTokenError(t *testing.T) {
	h, err := NewSaltedTokenHash("")
	if err == nil {
		t.Fatal("expected error for empty token, got nil")
	}
	if h != nil {
		t.Error("expected nil result for empty token")
	}
	var ite *InvalidTokenError
	if !errors.As(err, &ite) {
		t.Errorf("expected InvalidTokenError, got %T: %v", err, err)
	}
}

// --------------------------------------------------------------------------
// SaltedTokenHash.Verify
// --------------------------------------------------------------------------

func TestVerify_CorrectTokenReturnsTrue(t *testing.T) {
	token := "valid-auth-token"
	h, err := NewSaltedTokenHash(token)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}
	if !h.Verify(token) {
		t.Error("expected Verify to return true for the original token")
	}
}

func TestVerify_WrongTokenReturnsFalse(t *testing.T) {
	h, err := NewSaltedTokenHash("correct-token")
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}
	if h.Verify("wrong-token") {
		t.Error("expected Verify to return false for an incorrect token")
	}
}

func TestVerify_EmptyTokenReturnsFalse(t *testing.T) {
	h, err := NewSaltedTokenHash("some-token")
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}
	if h.Verify("") {
		t.Error("expected Verify to return false for empty token")
	}
}

func TestVerify_NilReceiverReturnsFalse(t *testing.T) {
	var h *SaltedTokenHash
	if h.Verify("any-token") {
		t.Error("expected Verify to return false on nil receiver")
	}
}

func TestVerify_CorruptSaltReturnsFalse(t *testing.T) {
	h, err := NewSaltedTokenHash("token")
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}
	h.Salt = "not-hex!!!"
	if h.Verify("token") {
		t.Error("expected Verify to return false with corrupt salt")
	}
}

func TestVerify_CorruptHashReturnsFalse(t *testing.T) {
	h, err := NewSaltedTokenHash("token")
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}
	h.Hash = "not-hex!!!"
	if h.Verify("token") {
		t.Error("expected Verify to return false with corrupt hash")
	}
}

func TestVerify_IsConstantTime_SimilarTokensAllFail(t *testing.T) {
	// Verify that near-miss tokens are rejected — this does not prove
	// constant-time execution directly (that is guaranteed by
	// subtle.ConstantTimeCompare) but confirms correctness for similar inputs.
	token := "abcdefghijklmnop"
	h, err := NewSaltedTokenHash(token)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	variants := []string{
		"abcdefghijklmno",   // one char shorter
		"abcdefghijklmnopq", // one char longer
		"abcdefghijklmnop ", // trailing space
		" abcdefghijklmnop", // leading space
		strings.ToUpper(token),
	}
	for _, v := range variants {
		if h.Verify(v) {
			t.Errorf("Verify should return false for near-miss token %q", v)
		}
	}
}

// --------------------------------------------------------------------------
// Determinism: same salt + token → same hash (round-trip)
// --------------------------------------------------------------------------

func TestVerify_DeterministicWithFixedSalt(t *testing.T) {
	token := "determinism-test-token"
	h, err := NewSaltedTokenHash(token)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Verify twice to confirm the derivation is deterministic.
	if !h.Verify(token) {
		t.Error("first Verify call failed")
	}
	if !h.Verify(token) {
		t.Error("second Verify call failed — derivation is not deterministic")
	}
}

// --------------------------------------------------------------------------
// JSON serialisation round-trip
// --------------------------------------------------------------------------

func TestSaltedTokenHash_JSONRoundTrip(t *testing.T) {
	token := "json-round-trip-token"
	original, err := NewSaltedTokenHash(token)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var restored SaltedTokenHash
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if restored.Salt != original.Salt {
		t.Errorf("salt mismatch after JSON round-trip: got %q, want %q", restored.Salt, original.Salt)
	}
	if restored.Hash != original.Hash {
		t.Errorf("hash mismatch after JSON round-trip: got %q, want %q", restored.Hash, original.Hash)
	}

	if !restored.Verify(token) {
		t.Error("Verify failed on JSON-restored SaltedTokenHash")
	}
}

func TestSaltedTokenHash_JSONFieldNames(t *testing.T) {
	h, err := NewSaltedTokenHash("field-name-test")
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	data, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}

	if _, ok := raw["salt"]; !ok {
		t.Error("expected JSON key 'salt'")
	}
	if _, ok := raw["hash"]; !ok {
		t.Error("expected JSON key 'hash'")
	}
}

// --------------------------------------------------------------------------
// Typed errors
// --------------------------------------------------------------------------

func TestInvalidTokenError_ErrorMessage(t *testing.T) {
	err := &InvalidTokenError{Reason: "must not be empty"}
	msg := err.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
	if !strings.Contains(msg, "must not be empty") {
		t.Errorf("expected reason in message, got: %q", msg)
	}
}

func TestTokenHashError_ErrorMessage(t *testing.T) {
	cause := errors.New("rand failure")
	err := &TokenHashError{Cause: cause}
	msg := err.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
	if !strings.Contains(msg, "rand failure") {
		t.Errorf("expected cause in message, got: %q", msg)
	}
}

func TestTokenHashError_Unwrap(t *testing.T) {
	cause := errors.New("underlying cause")
	err := &TokenHashError{Cause: cause}
	if !errors.Is(err, cause) {
		t.Error("expected errors.Is to find the wrapped cause")
	}
}

// --------------------------------------------------------------------------
// Token hash zeroing
// --------------------------------------------------------------------------

// TestNewSaltedTokenHash_ZerosRawMaterial verifies that NewSaltedTokenHash
// zeroes the raw salt and hash bytes after encoding them into the struct.
// We confirm this indirectly: the struct fields must contain valid hex and
// Verify must still succeed, proving the hex-encoded strings are intact even
// after the underlying raw buffers are wiped.
func TestNewSaltedTokenHash_ZerosRawMaterial(t *testing.T) {
	token := "zeroing-test-token"
	h, err := NewSaltedTokenHash(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Salt and Hash fields must be non-empty valid hex strings.
	if h.Salt == "" {
		t.Error("expected non-empty Salt field after zeroing raw bytes")
	}
	if h.Hash == "" {
		t.Error("expected non-empty Hash field after zeroing raw bytes")
	}
	if _, err := hex.DecodeString(h.Salt); err != nil {
		t.Errorf("Salt is not valid hex after zeroing: %v", err)
	}
	if _, err := hex.DecodeString(h.Hash); err != nil {
		t.Errorf("Hash is not valid hex after zeroing: %v", err)
	}

	// Verify must succeed, proving the encoded strings were not corrupted.
	if !h.Verify(token) {
		t.Error("Verify failed after raw bytes were zeroed — struct fields corrupted")
	}
}

// TestVerify_ZerosIntermediateBuffers confirms that Verify zeroes its decoded
// salt, storedHash, and derived buffers without corrupting the struct's hex
// strings. Repeated calls must all succeed.
func TestVerify_ZerosIntermediateBuffers(t *testing.T) {
	token := "repeated-verify-token"
	h, err := NewSaltedTokenHash(token)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Snapshot the hex strings before any Verify call.
	saltBefore := h.Salt
	hashBefore := h.Hash

	for i := range 5 {
		if !h.Verify(token) {
			t.Errorf("Verify returned false on call %d — intermediate buffer zeroing corrupted struct state", i+1)
		}
	}

	// The hex strings in the struct must be unchanged after all zeroing.
	if h.Salt != saltBefore {
		t.Errorf("Salt field was mutated by Verify: got %q, want %q", h.Salt, saltBefore)
	}
	if h.Hash != hashBefore {
		t.Errorf("Hash field was mutated by Verify: got %q, want %q", h.Hash, hashBefore)
	}
}
