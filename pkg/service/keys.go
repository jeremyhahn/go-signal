package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// KeyService defines the pre-key operations exposed to protocol handlers.
type KeyService interface {
	// StoreKeys persists all pre-keys supplied in the request for the given
	// account and device.
	StoreKeys(ctx context.Context, accountUUID string, deviceID uint64, req *keys.SetKeysRequest) error

	// StoreKeysForIdentity persists pre-keys into the ACI or PNI namespace.
	StoreKeysForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, req *keys.SetKeysRequest) error

	// GetPreKeys retrieves the pre-key bundle for a target account and
	// device, consuming one-time keys atomically.
	GetPreKeys(ctx context.Context, targetUUID string, deviceID uint64) (*keys.PreKeyResponseItem, error)

	// GetPreKeysForIdentity retrieves the pre-key bundle in the ACI or PNI
	// namespace, consuming one-time keys atomically.
	GetPreKeysForIdentity(ctx context.Context, target *accounts.Account, identity accounts.IdentityType, deviceID uint64) (*keys.PreKeyResponseItem, error)

	// GetPreKeyCount returns the current one-time key counts for a device.
	GetPreKeyCount(ctx context.Context, accountUUID string, deviceID uint64) (*keys.PreKeyState, error)

	// GetPreKeyCountForIdentity returns one-time key counts scoped to the
	// ACI or PNI namespace.
	GetPreKeyCountForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64) (*keys.PreKeyState, error)

	// StoreSignedPreKey replaces the signed pre-key for a device.
	StoreSignedPreKey(ctx context.Context, accountUUID string, deviceID uint64, key *keys.SignedPreKey) error

	// StoreSignedPreKeyForIdentity persists a signed pre-key into the ACI or
	// PNI namespace.
	StoreSignedPreKeyForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, key *keys.SignedPreKey) error

	// StoreKEMPreKeys appends a batch of KEM one-time pre-keys for a device.
	StoreKEMPreKeys(ctx context.Context, accountUUID string, deviceID uint64, preKeys []*keys.KEMSignedPreKey) error

	// GetSignedPreKeyForIdentity retrieves the current signed pre-key from the
	// ACI or PNI namespace.
	GetSignedPreKeyForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64) (*keys.SignedPreKey, error)

	// StoreKEMPreKeysForIdentity persists a batch of KEM one-time pre-keys
	// into the ACI or PNI namespace.
	StoreKEMPreKeysForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, preKeys []*keys.KEMSignedPreKey) error

	// StoreKEMLastResortPreKey persists the last-resort KEM pre-key for the
	// given account and device. Never consumed during session establishment.
	StoreKEMLastResortPreKey(ctx context.Context, accountUUID string, deviceID uint64, preKey *keys.KEMSignedPreKey) error

	// StoreKEMLastResortPreKeyForIdentity persists a KEM last-resort key
	// into the ACI or PNI namespace.
	StoreKEMLastResortPreKeyForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, preKey *keys.KEMSignedPreKey) error

	// ListAccountUUIDs returns every account UUID with pre-keys. Used
	// by the orphan-prekey sweeper.
	ListAccountUUIDs(ctx context.Context) ([]string, error)

	// DeleteAllForAccount removes every pre-key associated with the
	// given account UUID. Idempotent; safe to call from the orphan
	// sweeper.
	DeleteAllForAccount(ctx context.Context, accountUUID string) error
}

// Compile-time assertion: KeysManager must satisfy KeyService.
var _ KeyService = (*keys.KeysManager)(nil)

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

func (s *keyService) StoreKeysForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, req *keys.SetKeysRequest) error {
	return s.manager.StoreKeysForIdentity(ctx, acct, identity, deviceID, req)
}

func (s *keyService) GetPreKeys(ctx context.Context, targetUUID string, deviceID uint64) (*keys.PreKeyResponseItem, error) {
	return s.manager.GetPreKeys(ctx, targetUUID, deviceID)
}

func (s *keyService) GetPreKeysForIdentity(ctx context.Context, target *accounts.Account, identity accounts.IdentityType, deviceID uint64) (*keys.PreKeyResponseItem, error) {
	return s.manager.GetPreKeysForIdentity(ctx, target, identity, deviceID)
}

func (s *keyService) GetPreKeyCount(ctx context.Context, accountUUID string, deviceID uint64) (*keys.PreKeyState, error) {
	return s.manager.GetPreKeyCount(ctx, accountUUID, deviceID)
}

func (s *keyService) GetPreKeyCountForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64) (*keys.PreKeyState, error) {
	return s.manager.GetPreKeyCountForIdentity(ctx, acct, identity, deviceID)
}

func (s *keyService) StoreSignedPreKey(ctx context.Context, accountUUID string, deviceID uint64, key *keys.SignedPreKey) error {
	return s.manager.StoreSignedPreKey(ctx, accountUUID, deviceID, key)
}

func (s *keyService) StoreSignedPreKeyForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, key *keys.SignedPreKey) error {
	return s.manager.StoreSignedPreKeyForIdentity(ctx, acct, identity, deviceID, key)
}

func (s *keyService) StoreKEMPreKeys(ctx context.Context, accountUUID string, deviceID uint64, preKeys []*keys.KEMSignedPreKey) error {
	return s.manager.StoreKEMPreKeys(ctx, accountUUID, deviceID, preKeys)
}

func (s *keyService) GetSignedPreKeyForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64) (*keys.SignedPreKey, error) {
	return s.manager.GetSignedPreKeyForIdentity(ctx, acct, identity, deviceID)
}

func (s *keyService) StoreKEMPreKeysForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, preKeys []*keys.KEMSignedPreKey) error {
	return s.manager.StoreKEMPreKeysForIdentity(ctx, acct, identity, deviceID, preKeys)
}

func (s *keyService) StoreKEMLastResortPreKey(ctx context.Context, accountUUID string, deviceID uint64, preKey *keys.KEMSignedPreKey) error {
	return s.manager.StoreKEMLastResortPreKey(ctx, accountUUID, deviceID, preKey)
}

func (s *keyService) StoreKEMLastResortPreKeyForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, preKey *keys.KEMSignedPreKey) error {
	return s.manager.StoreKEMLastResortPreKeyForIdentity(ctx, acct, identity, deviceID, preKey)
}

func (s *keyService) ListAccountUUIDs(ctx context.Context) ([]string, error) {
	return s.manager.ListAccountUUIDs(ctx)
}

func (s *keyService) DeleteAllForAccount(ctx context.Context, accountUUID string) error {
	return s.manager.DeleteAllForAccount(ctx, accountUUID)
}
