// Package keys provides pre-key types, storage interfaces, and cryptographic
// validation for Signal pre-keys.
package keys

import (
	"strconv"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// signatureSize is the expected size of an XEdDSA signature in bytes.
const signatureSize = 64

// identityKeySize is the expected size of a serialized Curve25519 public key
// in bytes: 1 type-prefix byte (0x05) plus 32 key bytes.
const identityKeySize = 33

// InvalidPreKeySignatureError is returned when a pre-key signature fails
// cryptographic verification.
type InvalidPreKeySignatureError struct {
	// KeyID is the identifier of the key whose signature failed.
	KeyID uint64
	// KeyType describes whether the failure occurred on a "signed" or "kem"
	// pre-key.
	KeyType string
	// Reason provides a human-readable description of the failure.
	Reason string
}

func (e *InvalidPreKeySignatureError) Error() string {
	return e.KeyType + " pre-key " + strconv.FormatUint(e.KeyID, 10) +
		" has invalid signature: " + e.Reason
}

// ValidateSignedPreKey verifies the XEdDSA signature on an EC signed pre-key with a 33-byte identity key; an empty identity key skips the check.
func ValidateSignedPreKey(identityKey []byte, spk *SignedPreKey) error {
	if len(identityKey) == 0 {
		return nil
	}

	if len(identityKey) != identityKeySize {
		return &InvalidPreKeySignatureError{
			KeyID:   spk.KeyID,
			KeyType: "signed",
			Reason:  "identity key must be " + strconv.Itoa(identityKeySize) + " bytes",
		}
	}

	if len(spk.Signature) != signatureSize {
		return &InvalidPreKeySignatureError{
			KeyID:   spk.KeyID,
			KeyType: "signed",
			Reason:  "signature must be " + strconv.Itoa(signatureSize) + " bytes",
		}
	}

	// Prepend the DJB type byte to a raw 32-byte key, as the client signed.
	message := serializePublicKey(spk.PublicKey)
	if message == nil {
		return &InvalidPreKeySignatureError{
			KeyID:   spk.KeyID,
			KeyType: "signed",
			Reason:  "public key must be 32 or 33 bytes",
		}
	}

	pubKey, err := ecc.DecodePoint(identityKey, 0)
	if err != nil {
		return &InvalidPreKeySignatureError{
			KeyID:   spk.KeyID,
			KeyType: "signed",
			Reason:  "identity key is not a valid Curve25519 public key: " + err.Error(),
		}
	}

	var sig [signatureSize]byte
	copy(sig[:], spk.Signature)

	if !ecc.VerifySignature(pubKey, message, sig) {
		return &InvalidPreKeySignatureError{
			KeyID:   spk.KeyID,
			KeyType: "signed",
			Reason:  "signature verification failed",
		}
	}

	return nil
}

// ValidateKEMSignedPreKey verifies the XEdDSA signature over a KEM public key; an empty identity key skips the check.
func ValidateKEMSignedPreKey(identityKey []byte, kspk *KEMSignedPreKey) error {
	if len(identityKey) == 0 {
		return nil
	}

	if len(identityKey) != identityKeySize {
		return &InvalidPreKeySignatureError{
			KeyID:   kspk.KeyID,
			KeyType: "kem",
			Reason:  "identity key must be " + strconv.Itoa(identityKeySize) + " bytes",
		}
	}

	if len(kspk.Signature) != signatureSize {
		return &InvalidPreKeySignatureError{
			KeyID:   kspk.KeyID,
			KeyType: "kem",
			Reason:  "signature must be " + strconv.Itoa(signatureSize) + " bytes",
		}
	}

	if len(kspk.PublicKey) == 0 {
		return &InvalidPreKeySignatureError{
			KeyID:   kspk.KeyID,
			KeyType: "kem",
			Reason:  "public key must not be empty",
		}
	}

	pubKey, err := ecc.DecodePoint(identityKey, 0)
	if err != nil {
		return &InvalidPreKeySignatureError{
			KeyID:   kspk.KeyID,
			KeyType: "kem",
			Reason:  "identity key is not a valid Curve25519 public key: " + err.Error(),
		}
	}

	var sig [signatureSize]byte
	copy(sig[:], kspk.Signature)

	// KEM pre-key public keys are raw bytes (not Curve25519 EC keys) so the
	// message is the raw public key bytes, not a serialized EC key.
	if !ecc.VerifySignature(pubKey, kspk.PublicKey, sig) {
		return &InvalidPreKeySignatureError{
			KeyID:   kspk.KeyID,
			KeyType: "kem",
			Reason:  "signature verification failed",
		}
	}

	return nil
}

// ValidateAllSignedKeys validates every EC and KEM signed pre-key and returns the first InvalidPreKeySignatureError.
func ValidateAllSignedKeys(identityKey []byte, signedPreKeys []*SignedPreKey, kemPreKeys []*KEMSignedPreKey) error {
	for _, spk := range signedPreKeys {
		if err := ValidateSignedPreKey(identityKey, spk); err != nil {
			return err
		}
	}

	for _, kspk := range kemPreKeys {
		if err := ValidateKEMSignedPreKey(identityKey, kspk); err != nil {
			return err
		}
	}

	return nil
}

// serializePublicKey returns the 33-byte serialized key a client signed: 33 bytes as-is, 32 with 0x05 prepended, else nil.
func serializePublicKey(pub []byte) []byte {
	switch len(pub) {
	case 33:
		// Already serialized with type prefix.
		return pub
	case 32:
		// Prepend the DJB type byte.
		serialized := make([]byte, 33)
		serialized[0] = ecc.DjbType
		copy(serialized[1:], pub)
		return serialized
	default:
		return nil
	}
}
