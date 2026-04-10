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

// ValidateSignedPreKey verifies the XEdDSA signature on an EC signed pre-key.
//
// The identity key must be the 33-byte serialized Curve25519 public key
// (DJB type byte 0x05 followed by 32 key bytes). The signature covers the
// serialized public key bytes of the signed pre-key (also 33 bytes).
//
// If identityKey is empty the validation is skipped and nil is returned. This
// accommodates the bootstrap case where the server does not yet hold an
// identity key for the account.
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

	// The signed pre-key's public key must be provided in serialized form
	// (type byte + 32 key bytes). If the caller supplied raw 32-byte key
	// material, prepend the DJB type byte so that verification matches what
	// the Signal client signed.
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

// ValidateKEMSignedPreKey verifies the XEdDSA signature on a KEM signed
// pre-key.
//
// The identity key must be the 33-byte serialized Curve25519 public key.
// The signature covers the raw KEM public key bytes as the message.
//
// If identityKey is empty the validation is skipped and nil is returned.
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

// ValidateAllSignedKeys validates all EC signed pre-keys and KEM signed
// pre-keys against the provided identity key. It returns the first
// InvalidPreKeySignatureError encountered.
//
// If identityKey is empty or both slices are empty, nil is returned.
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

// serializePublicKey returns the message bytes to verify an EC signed pre-key
// signature. Signal clients sign the serialized form of the public key, which
// is the DJB type byte (0x05) prepended to the 32-byte raw key.
//
// If the supplied bytes are already 33 bytes long (i.e., already include the
// type prefix) they are returned as-is. If they are 32 bytes the type prefix
// is prepended. Any other length returns nil.
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
