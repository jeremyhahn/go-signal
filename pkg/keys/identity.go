package keys

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// Identity-namespaced pre-key access.
//
// Every Signal account has two identifier namespaces (ACI and PNI; see
// accounts.IdentityType). Pre-keys, signed pre-keys, and KEM keys each
// live in their own namespace so clients authenticating against the PNI
// cannot consume ACI-targeted keys and vice versa.
//
// The existing KeysManager methods take a bare UUID string. For ACI
// flows callers pass Account.UUID; for PNI flows they pass Account.PNI.
// The *ForIdentity helpers below make that choice explicit:
//
//	// ACI flow:
//	m.StoreKeysForIdentity(ctx, acct, accounts.IdentityTypeACI, deviceID, req)
//
//	// PNI flow (bound to the phone-number identity):
//	m.StoreKeysForIdentity(ctx, acct, accounts.IdentityTypePNI, deviceID, req)
//
// Both paths use the same underlying storage; the "namespace" is just
// the key prefix chosen by which UUID string is passed to the store.

// ErrIdentityNotSet is returned when the requested identity namespace
// has no UUID on the account. PNI is optional on some legacy records;
// ACI is never empty on a validly-created account.
var ErrIdentityNotSet = signalerrors.New(signalerrors.ErrInvalidArgument, "identity UUID is not set on account")

// resolveIdentityUUID returns the UUID for the requested identity
// namespace, or ErrIdentityNotSet when the account does not carry a
// value for that identity.
func resolveIdentityUUID(acct *accounts.Account, identity accounts.IdentityType) (string, error) {
	if acct == nil {
		return "", signalerrors.New(signalerrors.ErrInvalidArgument, "account must not be nil")
	}
	uuid := acct.IdentityUUID(identity)
	if uuid == "" {
		return "", ErrIdentityNotSet
	}
	return uuid, nil
}

// StoreKeysForIdentity persists pre-keys into the namespace identified
// by identity. See KeysManager.StoreKeys for semantics.
func (m *KeysManager) StoreKeysForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, req *SetKeysRequest) error {
	uuid, err := resolveIdentityUUID(acct, identity)
	if err != nil {
		return err
	}
	return m.StoreKeys(ctx, uuid, deviceID, req)
}

// GetPreKeysForIdentity returns the pre-key bundle in the namespace
// identified by identity. See KeysManager.GetPreKeys for semantics.
func (m *KeysManager) GetPreKeysForIdentity(ctx context.Context, target *accounts.Account, identity accounts.IdentityType, deviceID uint64) (*PreKeyResponseItem, error) {
	uuid, err := resolveIdentityUUID(target, identity)
	if err != nil {
		return nil, err
	}
	return m.GetPreKeys(ctx, uuid, deviceID)
}

// GetPreKeyCountForIdentity returns one-time key counts scoped to the
// given identity.
func (m *KeysManager) GetPreKeyCountForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64) (*PreKeyState, error) {
	uuid, err := resolveIdentityUUID(acct, identity)
	if err != nil {
		return nil, err
	}
	return m.GetPreKeyCount(ctx, uuid, deviceID)
}

// StoreSignedPreKeyForIdentity persists a signed pre-key into the
// namespace identified by identity.
func (m *KeysManager) StoreSignedPreKeyForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, key *SignedPreKey) error {
	uuid, err := resolveIdentityUUID(acct, identity)
	if err != nil {
		return err
	}
	return m.StoreSignedPreKey(ctx, uuid, deviceID, key)
}

// GetSignedPreKeyForIdentity retrieves the current signed pre-key from the
// namespace identified by identity. Used by callers that need to verify
// identity-routed uploads landed in the correct partition.
func (m *KeysManager) GetSignedPreKeyForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64) (*SignedPreKey, error) {
	uuid, err := resolveIdentityUUID(acct, identity)
	if err != nil {
		return nil, err
	}
	return m.store.GetSignedPreKey(ctx, uuid, deviceID)
}

// StoreKEMPreKeysForIdentity persists a batch of KEM one-time pre-keys
// into the namespace identified by identity.
func (m *KeysManager) StoreKEMPreKeysForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, preKeys []*KEMSignedPreKey) error {
	uuid, err := resolveIdentityUUID(acct, identity)
	if err != nil {
		return err
	}
	return m.StoreKEMPreKeys(ctx, uuid, deviceID, preKeys)
}

// StoreKEMLastResortPreKeyForIdentity persists a KEM last-resort key
// into the namespace identified by identity.
func (m *KeysManager) StoreKEMLastResortPreKeyForIdentity(ctx context.Context, acct *accounts.Account, identity accounts.IdentityType, deviceID uint64, preKey *KEMSignedPreKey) error {
	uuid, err := resolveIdentityUUID(acct, identity)
	if err != nil {
		return err
	}
	return m.StoreKEMLastResortPreKey(ctx, uuid, deviceID, preKey)
}
