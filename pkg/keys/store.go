package keys

import "context"

// PreKeyStore defines the storage interface for Signal pre-key distribution.
type PreKeyStore interface {
	// StoreECPreKeys persists a batch of EC one-time pre-keys for a device.
	StoreECPreKeys(ctx context.Context, uuid string, deviceID uint64, preKeys []*PreKey) error

	// StoreKEMPreKeys persists a batch of KEM one-time pre-keys for a device.
	StoreKEMPreKeys(ctx context.Context, uuid string, deviceID uint64, preKeys []*KEMSignedPreKey) error

	// StoreKEMLastResortPreKey persists the last-resort KEM pre-key for a device.
	// This key must never be consumed (deleted) during session establishment.
	// Calling this method replaces any previously stored last-resort key.
	StoreKEMLastResortPreKey(ctx context.Context, uuid string, deviceID uint64, preKey *KEMSignedPreKey) error

	// StoreSignedPreKey persists the current signed pre-key for a device.
	StoreSignedPreKey(ctx context.Context, uuid string, deviceID uint64, signedPreKey *SignedPreKey) error

	// TakeEC removes and returns one EC pre-key for a device.
	TakeEC(ctx context.Context, uuid string, deviceID uint64) (*PreKey, error)

	// TakeKEM removes and returns one KEM one-time pre-key for a device.
	// The returned key is consumed (deleted). When one-time keys are exhausted,
	// callers must fall back to GetKEMLastResortPreKey.
	TakeKEM(ctx context.Context, uuid string, deviceID uint64) (*KEMSignedPreKey, error)

	// GetKEMLastResortPreKey retrieves the last-resort KEM pre-key for a device
	// without consuming it. Returns an error if no last-resort key is stored.
	GetKEMLastResortPreKey(ctx context.Context, uuid string, deviceID uint64) (*KEMSignedPreKey, error)

	// GetSignedPreKey retrieves the current signed pre-key for a device.
	GetSignedPreKey(ctx context.Context, uuid string, deviceID uint64) (*SignedPreKey, error)

	// GetPreKeyCount returns the count of remaining pre-keys for a device.
	GetPreKeyCount(ctx context.Context, uuid string, deviceID uint64) (*PreKeyState, error)

	// DeleteAllForDevice removes all pre-keys associated with a device.
	DeleteAllForDevice(ctx context.Context, uuid string, deviceID uint64) error

	// DeleteAllForAccount removes all pre-keys associated with an account.
	DeleteAllForAccount(ctx context.Context, uuid string) error
}
