// Package keys provides pre-key types and storage interfaces for the Signal server.
package keys

// PreKey represents a one-time pre-key used for session establishment.
type PreKey struct {
	KeyID     uint64
	PublicKey []byte
}

// SignedPreKey represents a signed pre-key with a signature for verification.
type SignedPreKey struct {
	KeyID     uint64
	PublicKey []byte
	Signature []byte
}

// KEMSignedPreKey represents a post-quantum KEM signed pre-key.
// When IsLastResort is true, the key is a last-resort key and must never be
// consumed (deleted) during session establishment. It is returned when
// one-time KEM pre-keys are exhausted.
type KEMSignedPreKey struct {
	KeyID        uint64
	PublicKey    []byte
	Signature    []byte
	IsLastResort bool
}

// PreKeyBundle groups all key material needed to establish a session.
type PreKeyBundle struct {
	IdentityKey  []byte
	PreKey       *PreKey
	SignedPreKey *SignedPreKey
	KEMPreKey    *KEMSignedPreKey
}

// PreKeyState represents the count of remaining pre-keys for a device.
type PreKeyState struct {
	ECCount  int
	KEMCount int
	// HasLastResort indicates whether a KEM last-resort pre-key is stored.
	HasLastResort bool
}

// PreKeyResponse is returned when fetching pre-keys for a target account.
// It contains the identity key and per-device pre-key bundles needed to
// establish a new Signal session.
type PreKeyResponse struct {
	IdentityKey []byte               `json:"identityKey"`
	Devices     []PreKeyResponseItem `json:"devices"`
}

// PreKeyResponseItem contains the pre-key bundle for a single device.
type PreKeyResponseItem struct {
	DeviceID       uint64           `json:"deviceId"`
	RegistrationID uint32           `json:"registrationId"`
	SignedPreKey   *SignedPreKey    `json:"signedPreKey"`
	PreKey         *PreKey          `json:"preKey,omitempty"`
	KEMPreKey      *KEMSignedPreKey `json:"pqPreKey,omitempty"`
}

// SetKeysRequest is the client request to upload new pre-keys to the server.
type SetKeysRequest struct {
	PreKeys      []*PreKey          `json:"preKeys"`
	SignedPreKey *SignedPreKey      `json:"signedPreKey"`
	KEMPreKeys   []*KEMSignedPreKey `json:"pqPreKeys"`
	// KEMLastResortPreKey is the last-resort KEM pre-key that is never consumed.
	// It is stored separately and returned only when one-time KEM pre-keys are
	// exhausted. Setting this field replaces any previously stored last-resort key.
	KEMLastResortPreKey *KEMSignedPreKey `json:"pqLastResortPreKey,omitempty"`
}

// SendKeysResponse is returned after successfully processing a SetKeysRequest.
type SendKeysResponse struct {
	// Empty for now; placeholder for future fields.
}
