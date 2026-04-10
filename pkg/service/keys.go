package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// KeyService defines the pre-key operations exposed to protocol handlers.
type KeyService interface {
	// StoreKeys persists all pre-keys supplied in the request for the given
	// account and device.
	StoreKeys(ctx context.Context, accountUUID string, deviceID uint64, req *keys.SetKeysRequest) error

	// GetPreKeys retrieves the pre-key bundle for a target account and
	// device, consuming one-time keys atomically.
	GetPreKeys(ctx context.Context, targetUUID string, deviceID uint64) (*keys.PreKeyResponseItem, error)

	// GetPreKeyCount returns the current one-time key counts for a device.
	GetPreKeyCount(ctx context.Context, accountUUID string, deviceID uint64) (*keys.PreKeyState, error)

	// StoreSignedPreKey replaces the signed pre-key for a device.
	StoreSignedPreKey(ctx context.Context, accountUUID string, deviceID uint64, key *keys.SignedPreKey) error

	// StoreKEMPreKeys appends a batch of KEM one-time pre-keys for a device.
	StoreKEMPreKeys(ctx context.Context, accountUUID string, deviceID uint64, preKeys []*keys.KEMSignedPreKey) error
}

// keyService is the default KeyService backed by a KeysManager.
type keyService struct {
	manager *keys.KeysManager
}

// NewKeyService returns a KeyService that delegates to the given KeysManager.
// The manager must not be nil.
func NewKeyService(manager *keys.KeysManager) KeyService {
	return &keyService{manager: manager}
}

func (s *keyService) StoreKeys(ctx context.Context, accountUUID string, deviceID uint64, req *keys.SetKeysRequest) error {
	return s.manager.StoreKeys(ctx, accountUUID, deviceID, req)
}

func (s *keyService) GetPreKeys(ctx context.Context, targetUUID string, deviceID uint64) (*keys.PreKeyResponseItem, error) {
	return s.manager.GetPreKeys(ctx, targetUUID, deviceID)
}

func (s *keyService) GetPreKeyCount(ctx context.Context, accountUUID string, deviceID uint64) (*keys.PreKeyState, error) {
	return s.manager.GetPreKeyCount(ctx, accountUUID, deviceID)
}

func (s *keyService) StoreSignedPreKey(ctx context.Context, accountUUID string, deviceID uint64, key *keys.SignedPreKey) error {
	return s.manager.StoreSignedPreKey(ctx, accountUUID, deviceID, key)
}

func (s *keyService) StoreKEMPreKeys(ctx context.Context, accountUUID string, deviceID uint64, preKeys []*keys.KEMSignedPreKey) error {
	return s.manager.StoreKEMPreKeys(ctx, accountUUID, deviceID, preKeys)
}
