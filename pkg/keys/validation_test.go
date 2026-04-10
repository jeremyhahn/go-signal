package keys

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// generateTestKeyPair generates a real Curve25519 key pair for testing.
func generateTestKeyPair(t *testing.T) *ecc.ECKeyPair {
	t.Helper()
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return kp
}

// signMessage signs message with the given key pair using XEdDSA and returns
// the 64-byte signature.
func signMessage(t *testing.T, kp *ecc.ECKeyPair, message []byte) []byte {
	t.Helper()
	sig, err := ecc.CalculateSignature(kp.PrivateKey(), message)
	if err != nil {
		t.Fatalf("failed to sign message: %v", err)
	}
	return sig[:]
}

// identityKeyBytes returns the serialized identity key (33 bytes) for a key pair.
func identityKeyBytes(kp *ecc.ECKeyPair) []byte {
	return kp.PublicKey().Serialize()
}

// TestValidateSignedPreKey_ValidSignature tests that a correctly signed pre-key passes.
func TestValidateSignedPreKey_ValidSignature(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	// The pre-key public key (Curve25519) serialized as 33 bytes.
	preKeyKP := generateTestKeyPair(t)
	spkPub := preKeyKP.PublicKey().Serialize() // 33 bytes
	sig := signMessage(t, kp, spkPub)

	spk := &SignedPreKey{
		KeyID:     1,
		PublicKey: spkPub,
		Signature: sig,
	}

	if err := ValidateSignedPreKey(idKey, spk); err != nil {
		t.Errorf("expected no error for valid signature, got: %v", err)
	}
}

// TestValidateSignedPreKey_ValidSignature32ByteKey tests validation when the
// pre-key public key is stored as 32 raw bytes (without the type prefix).
func TestValidateSignedPreKey_ValidSignature32ByteKey(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	preKeyKP := generateTestKeyPair(t)
	// The client signs the serialized (33-byte) public key.
	spkPubSerialized := preKeyKP.PublicKey().Serialize()
	sig := signMessage(t, kp, spkPubSerialized)

	// Store only the raw 32 bytes — ValidateSignedPreKey should prepend the
	// DJB type byte before verification.
	raw32 := spkPubSerialized[1:]

	spk := &SignedPreKey{
		KeyID:     2,
		PublicKey: raw32,
		Signature: sig,
	}

	if err := ValidateSignedPreKey(idKey, spk); err != nil {
		t.Errorf("expected no error for valid signature with 32-byte key, got: %v", err)
	}
}

// TestValidateSignedPreKey_InvalidSignature tests that a tampered signature is rejected.
func TestValidateSignedPreKey_InvalidSignature(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	preKeyKP := generateTestKeyPair(t)
	spkPub := preKeyKP.PublicKey().Serialize()

	// Corrupt the signature.
	badSig := make([]byte, signatureSize)
	for i := range badSig {
		badSig[i] = 0xFF
	}

	spk := &SignedPreKey{
		KeyID:     1,
		PublicKey: spkPub,
		Signature: badSig,
	}

	err := ValidateSignedPreKey(idKey, spk)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
	var sigErr *InvalidPreKeySignatureError
	if e, ok := err.(*InvalidPreKeySignatureError); !ok {
		t.Fatalf("expected *InvalidPreKeySignatureError, got %T", err)
	} else {
		sigErr = e
	}
	if sigErr.KeyID != 1 {
		t.Errorf("expected KeyID 1, got %d", sigErr.KeyID)
	}
	if sigErr.KeyType != "signed" {
		t.Errorf("expected KeyType 'signed', got %q", sigErr.KeyType)
	}
}

// TestValidateSignedPreKey_WrongIdentityKey tests that the wrong identity key is rejected.
func TestValidateSignedPreKey_WrongIdentityKey(t *testing.T) {
	kp := generateTestKeyPair(t)
	wrongKP := generateTestKeyPair(t)
	// Use wrong identity key for verification.
	wrongIdKey := identityKeyBytes(wrongKP)

	preKeyKP := generateTestKeyPair(t)
	spkPub := preKeyKP.PublicKey().Serialize()
	sig := signMessage(t, kp, spkPub) // signed with kp, not wrongKP

	spk := &SignedPreKey{
		KeyID:     1,
		PublicKey: spkPub,
		Signature: sig,
	}

	err := ValidateSignedPreKey(wrongIdKey, spk)
	if err == nil {
		t.Fatal("expected error when verifying with wrong identity key")
	}
}

// TestValidateSignedPreKey_EmptyIdentityKey tests that empty identity key skips validation.
func TestValidateSignedPreKey_EmptyIdentityKey(t *testing.T) {
	spk := &SignedPreKey{
		KeyID:     1,
		PublicKey: []byte{0x01},
		Signature: []byte{0x02},
	}
	if err := ValidateSignedPreKey(nil, spk); err != nil {
		t.Errorf("expected nil error for empty identity key, got: %v", err)
	}
	if err := ValidateSignedPreKey([]byte{}, spk); err != nil {
		t.Errorf("expected nil error for empty identity key slice, got: %v", err)
	}
}

// TestValidateSignedPreKey_ShortSignature tests that a too-short signature is rejected.
func TestValidateSignedPreKey_ShortSignature(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	spk := &SignedPreKey{
		KeyID:     1,
		PublicKey: make([]byte, 33),
		Signature: []byte{0x01, 0x02}, // only 2 bytes, must be 64
	}

	err := ValidateSignedPreKey(idKey, spk)
	if err == nil {
		t.Fatal("expected error for short signature")
	}
	if _, ok := err.(*InvalidPreKeySignatureError); !ok {
		t.Fatalf("expected *InvalidPreKeySignatureError, got %T", err)
	}
}

// TestValidateSignedPreKey_ShortPublicKey tests that a public key of invalid length is rejected.
func TestValidateSignedPreKey_ShortPublicKey(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	spk := &SignedPreKey{
		KeyID:     1,
		PublicKey: []byte{0x01, 0x02}, // only 2 bytes, must be 32 or 33
		Signature: make([]byte, signatureSize),
	}

	err := ValidateSignedPreKey(idKey, spk)
	if err == nil {
		t.Fatal("expected error for short public key")
	}
	if _, ok := err.(*InvalidPreKeySignatureError); !ok {
		t.Fatalf("expected *InvalidPreKeySignatureError, got %T", err)
	}
}

// TestValidateSignedPreKey_InvalidIdentityKeyLength tests that an identity
// key with incorrect length is rejected.
func TestValidateSignedPreKey_InvalidIdentityKeyLength(t *testing.T) {
	// Identity key of wrong length (not 33 bytes).
	badIdKey := []byte{0x01, 0x02, 0x03}

	spk := &SignedPreKey{
		KeyID:     1,
		PublicKey: make([]byte, 33),
		Signature: make([]byte, signatureSize),
	}

	err := ValidateSignedPreKey(badIdKey, spk)
	if err == nil {
		t.Fatal("expected error for invalid identity key length")
	}
	if _, ok := err.(*InvalidPreKeySignatureError); !ok {
		t.Fatalf("expected *InvalidPreKeySignatureError, got %T", err)
	}
}

// TestValidateKEMSignedPreKey_ValidSignature tests that a correctly signed KEM pre-key passes.
func TestValidateKEMSignedPreKey_ValidSignature(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	// KEM public key is an arbitrary byte slice (not a Curve25519 key).
	kemPub := make([]byte, 1568) // Kyber-1024 public key size
	for i := range kemPub {
		kemPub[i] = byte(i)
	}
	sig := signMessage(t, kp, kemPub)

	kspk := &KEMSignedPreKey{
		KeyID:     10,
		PublicKey: kemPub,
		Signature: sig,
	}

	if err := ValidateKEMSignedPreKey(idKey, kspk); err != nil {
		t.Errorf("expected no error for valid KEM signature, got: %v", err)
	}
}

// TestValidateKEMSignedPreKey_InvalidSignature tests that a tampered KEM signature is rejected.
func TestValidateKEMSignedPreKey_InvalidSignature(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	kemPub := make([]byte, 64)
	badSig := make([]byte, signatureSize)

	kspk := &KEMSignedPreKey{
		KeyID:     10,
		PublicKey: kemPub,
		Signature: badSig,
	}

	err := ValidateKEMSignedPreKey(idKey, kspk)
	if err == nil {
		t.Fatal("expected error for invalid KEM signature")
	}
	e, ok := err.(*InvalidPreKeySignatureError)
	if !ok {
		t.Fatalf("expected *InvalidPreKeySignatureError, got %T", err)
	}
	if e.KeyType != "kem" {
		t.Errorf("expected KeyType 'kem', got %q", e.KeyType)
	}
}

// TestValidateKEMSignedPreKey_WrongIdentityKey tests that the wrong identity key rejects a KEM key.
func TestValidateKEMSignedPreKey_WrongIdentityKey(t *testing.T) {
	kp := generateTestKeyPair(t)
	wrongKP := generateTestKeyPair(t)
	wrongIdKey := identityKeyBytes(wrongKP)

	kemPub := make([]byte, 64)
	for i := range kemPub {
		kemPub[i] = byte(i)
	}
	sig := signMessage(t, kp, kemPub)

	kspk := &KEMSignedPreKey{
		KeyID:     10,
		PublicKey: kemPub,
		Signature: sig,
	}

	err := ValidateKEMSignedPreKey(wrongIdKey, kspk)
	if err == nil {
		t.Fatal("expected error when verifying KEM key with wrong identity key")
	}
}

// TestValidateKEMSignedPreKey_EmptyIdentityKey tests skip behavior for empty identity key.
func TestValidateKEMSignedPreKey_EmptyIdentityKey(t *testing.T) {
	kspk := &KEMSignedPreKey{
		KeyID:     10,
		PublicKey: []byte{0x01},
		Signature: []byte{0x02},
	}
	if err := ValidateKEMSignedPreKey(nil, kspk); err != nil {
		t.Errorf("expected nil error for empty identity key, got: %v", err)
	}
	if err := ValidateKEMSignedPreKey([]byte{}, kspk); err != nil {
		t.Errorf("expected nil error for empty identity key slice, got: %v", err)
	}
}

// TestValidateKEMSignedPreKey_ShortSignature tests that a too-short KEM signature is rejected.
func TestValidateKEMSignedPreKey_ShortSignature(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	kspk := &KEMSignedPreKey{
		KeyID:     10,
		PublicKey: make([]byte, 64),
		Signature: []byte{0x01}, // too short
	}

	err := ValidateKEMSignedPreKey(idKey, kspk)
	if err == nil {
		t.Fatal("expected error for short KEM signature")
	}
	if _, ok := err.(*InvalidPreKeySignatureError); !ok {
		t.Fatalf("expected *InvalidPreKeySignatureError, got %T", err)
	}
}

// TestValidateKEMSignedPreKey_EmptyPublicKey tests that an empty KEM public key is rejected.
func TestValidateKEMSignedPreKey_EmptyPublicKey(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	kspk := &KEMSignedPreKey{
		KeyID:     10,
		PublicKey: nil,
		Signature: make([]byte, signatureSize),
	}

	err := ValidateKEMSignedPreKey(idKey, kspk)
	if err == nil {
		t.Fatal("expected error for empty KEM public key")
	}
	if _, ok := err.(*InvalidPreKeySignatureError); !ok {
		t.Fatalf("expected *InvalidPreKeySignatureError, got %T", err)
	}
}

// TestValidateKEMSignedPreKey_InvalidIdentityKeyLength tests that a KEM key
// with invalid identity key length is rejected.
func TestValidateKEMSignedPreKey_InvalidIdentityKeyLength(t *testing.T) {
	badIdKey := []byte{0x01, 0x02}

	kspk := &KEMSignedPreKey{
		KeyID:     10,
		PublicKey: make([]byte, 64),
		Signature: make([]byte, signatureSize),
	}

	err := ValidateKEMSignedPreKey(badIdKey, kspk)
	if err == nil {
		t.Fatal("expected error for invalid identity key length")
	}
}

// TestValidateAllSignedKeys_EmptySlices tests that empty slices return nil.
func TestValidateAllSignedKeys_EmptySlices(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	if err := ValidateAllSignedKeys(idKey, nil, nil); err != nil {
		t.Errorf("expected nil for empty slices, got: %v", err)
	}

	if err := ValidateAllSignedKeys(idKey, []*SignedPreKey{}, []*KEMSignedPreKey{}); err != nil {
		t.Errorf("expected nil for empty slices, got: %v", err)
	}
}

// TestValidateAllSignedKeys_AllValid tests that all valid keys pass.
func TestValidateAllSignedKeys_AllValid(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	spk1KP := generateTestKeyPair(t)
	spk1Pub := spk1KP.PublicKey().Serialize()
	spk1Sig := signMessage(t, kp, spk1Pub)

	spk2KP := generateTestKeyPair(t)
	spk2Pub := spk2KP.PublicKey().Serialize()
	spk2Sig := signMessage(t, kp, spk2Pub)

	kemPub := make([]byte, 64)
	kemSig := signMessage(t, kp, kemPub)

	spks := []*SignedPreKey{
		{KeyID: 1, PublicKey: spk1Pub, Signature: spk1Sig},
		{KeyID: 2, PublicKey: spk2Pub, Signature: spk2Sig},
	}
	kems := []*KEMSignedPreKey{
		{KeyID: 100, PublicKey: kemPub, Signature: kemSig},
	}

	if err := ValidateAllSignedKeys(idKey, spks, kems); err != nil {
		t.Errorf("expected no error for all valid keys, got: %v", err)
	}
}

// TestValidateAllSignedKeys_InvalidSignedPreKey tests early exit on invalid SPK.
func TestValidateAllSignedKeys_InvalidSignedPreKey(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	spkKP := generateTestKeyPair(t)
	spkPub := spkKP.PublicKey().Serialize()

	badSig := make([]byte, signatureSize)

	spks := []*SignedPreKey{
		{KeyID: 1, PublicKey: spkPub, Signature: badSig},
	}

	err := ValidateAllSignedKeys(idKey, spks, nil)
	if err == nil {
		t.Fatal("expected error for invalid signed pre-key")
	}
	if _, ok := err.(*InvalidPreKeySignatureError); !ok {
		t.Fatalf("expected *InvalidPreKeySignatureError, got %T", err)
	}
}

// TestValidateAllSignedKeys_InvalidKEMKey tests early exit on invalid KEM key.
func TestValidateAllSignedKeys_InvalidKEMKey(t *testing.T) {
	kp := generateTestKeyPair(t)
	idKey := identityKeyBytes(kp)

	kemPub := make([]byte, 64)
	badSig := make([]byte, signatureSize)

	kems := []*KEMSignedPreKey{
		{KeyID: 100, PublicKey: kemPub, Signature: badSig},
	}

	err := ValidateAllSignedKeys(idKey, nil, kems)
	if err == nil {
		t.Fatal("expected error for invalid KEM pre-key")
	}
	if _, ok := err.(*InvalidPreKeySignatureError); !ok {
		t.Fatalf("expected *InvalidPreKeySignatureError, got %T", err)
	}
}

// TestValidateAllSignedKeys_EmptyIdentityKey tests that empty identity key skips validation.
func TestValidateAllSignedKeys_EmptyIdentityKey(t *testing.T) {
	spks := []*SignedPreKey{
		{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}},
	}
	kems := []*KEMSignedPreKey{
		{KeyID: 100, PublicKey: []byte{0x03}, Signature: []byte{0x04}},
	}

	if err := ValidateAllSignedKeys(nil, spks, kems); err != nil {
		t.Errorf("expected nil for empty identity key, got: %v", err)
	}
}

// TestInvalidPreKeySignatureError_Error tests the error message format.
func TestInvalidPreKeySignatureError_Error(t *testing.T) {
	e := &InvalidPreKeySignatureError{
		KeyID:   42,
		KeyType: "signed",
		Reason:  "signature verification failed",
	}
	msg := e.Error()
	if msg == "" {
		t.Fatal("expected non-empty error message")
	}
	expected := "signed pre-key 42 has invalid signature: signature verification failed"
	if msg != expected {
		t.Errorf("expected %q, got %q", expected, msg)
	}
}

// TestInvalidPreKeySignatureError_KEM tests the error message for KEM key type.
func TestInvalidPreKeySignatureError_KEM(t *testing.T) {
	e := &InvalidPreKeySignatureError{
		KeyID:   7,
		KeyType: "kem",
		Reason:  "signature must be 64 bytes",
	}
	msg := e.Error()
	expected := "kem pre-key 7 has invalid signature: signature must be 64 bytes"
	if msg != expected {
		t.Errorf("expected %q, got %q", expected, msg)
	}
}

// TestSerializePublicKey_33Bytes tests passthrough of already-serialized keys.
func TestSerializePublicKey_33Bytes(t *testing.T) {
	pub := make([]byte, 33)
	pub[0] = ecc.DjbType
	result := serializePublicKey(pub)
	if len(result) != 33 {
		t.Errorf("expected 33 bytes, got %d", len(result))
	}
	if result[0] != ecc.DjbType {
		t.Errorf("expected type byte 0x%02x, got 0x%02x", ecc.DjbType, result[0])
	}
}

// TestSerializePublicKey_32Bytes tests that the type prefix is prepended.
func TestSerializePublicKey_32Bytes(t *testing.T) {
	pub := make([]byte, 32)
	pub[0] = 0xAA
	result := serializePublicKey(pub)
	if len(result) != 33 {
		t.Errorf("expected 33 bytes, got %d", len(result))
	}
	if result[0] != ecc.DjbType {
		t.Errorf("expected type byte 0x%02x, got 0x%02x", ecc.DjbType, result[0])
	}
	if result[1] != 0xAA {
		t.Errorf("expected first key byte 0xAA, got 0x%02x", result[1])
	}
}

// TestSerializePublicKey_InvalidLength tests nil return for invalid lengths.
func TestSerializePublicKey_InvalidLength(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x01},
		make([]byte, 31),
		make([]byte, 34),
		make([]byte, 100),
	}
	for _, pub := range cases {
		if result := serializePublicKey(pub); result != nil {
			t.Errorf("expected nil for length %d, got %v", len(pub), result)
		}
	}
}
