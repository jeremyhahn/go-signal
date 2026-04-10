package keys

import (
	"context"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// KeysManager coordinates pre-key storage and retrieval operations. It wraps a
// PreKeyStore implementation and provides higher-level business logic for key
// management workflows.
type KeysManager struct {
	store PreKeyStore
}

// NewKeysManager creates a new KeysManager backed by the provided PreKeyStore.
func NewKeysManager(store PreKeyStore) *KeysManager {
	return &KeysManager{store: store}
}

// StoreKeys processes a SetKeysRequest and persists all provided pre-keys for
// the given account and device. Each key type is stored independently; the first
// encountered error is returned. The KEMLastResortPreKey, if present, is stored
// separately and is never consumed during session establishment.
func (m *KeysManager) StoreKeys(ctx context.Context, accountUUID string, deviceID uint64, req *SetKeysRequest) error {
	if req == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "set keys request must not be nil")
	}

	if len(req.PreKeys) > 0 {
		if err := m.store.StoreECPreKeys(ctx, accountUUID, deviceID, req.PreKeys); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "failed to store EC pre-keys", err)
		}
	}

	if req.SignedPreKey != nil {
		if err := m.store.StoreSignedPreKey(ctx, accountUUID, deviceID, req.SignedPreKey); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "failed to store signed pre-key", err)
		}
	}

	if len(req.KEMPreKeys) > 0 {
		if err := m.store.StoreKEMPreKeys(ctx, accountUUID, deviceID, req.KEMPreKeys); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "failed to store KEM pre-keys", err)
		}
	}

	// Store the last-resort KEM pre-key separately. It must not be mixed with
	// one-time KEM keys and must never be consumed during session establishment.
	if req.KEMLastResortPreKey != nil {
		if err := m.store.StoreKEMLastResortPreKey(ctx, accountUUID, deviceID, req.KEMLastResortPreKey); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "failed to store KEM last-resort pre-key", err)
		}
	}

	return nil
}

// GetPreKeys retrieves the pre-key bundle for a target account and device. This
// is used during session establishment by the sending client.
//
// One-time EC pre-keys are consumed (deleted) upon retrieval. If no one-time EC
// pre-keys remain, the bundle is returned without a PreKey field.
//
// For KEM pre-keys the following precedence applies:
//  1. If one-time KEM pre-keys are available, one is consumed and returned.
//  2. If no one-time KEM pre-keys remain, the last-resort KEM pre-key is
//     returned WITHOUT being consumed (deleted), so it remains available for
//     future session establishments. This is the correct Signal protocol
//     behaviour: last-resort keys are never deleted by the server.
func (m *KeysManager) GetPreKeys(ctx context.Context, targetUUID string, deviceID uint64) (*PreKeyResponseItem, error) {
	signedPreKey, err := m.store.GetSignedPreKey(ctx, targetUUID, deviceID)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrPreKeyNotAvailable, "failed to get signed pre-key", err)
	}

	item := &PreKeyResponseItem{
		DeviceID:     deviceID,
		SignedPreKey: signedPreKey,
	}

	// Attempt to take a one-time EC pre-key. Not having one is non-fatal;
	// session establishment can proceed without it.
	ecPreKey, err := m.store.TakeEC(ctx, targetUUID, deviceID)
	if err == nil {
		item.PreKey = ecPreKey
	}

	// Attempt to take a one-time KEM pre-key. If none remain, fall back to the
	// last-resort KEM pre-key without consuming it.
	kemPreKey, err := m.store.TakeKEM(ctx, targetUUID, deviceID)
	if err == nil {
		item.KEMPreKey = kemPreKey
	} else {
		// One-time KEM keys exhausted: return the last-resort key without removing it.
		lastResort, lrErr := m.store.GetKEMLastResortPreKey(ctx, targetUUID, deviceID)
		if lrErr == nil {
			item.KEMPreKey = lastResort
		}
	}

	return item, nil
}

// GetPreKeyCount returns the current pre-key counts for the given account and
// device, reporting both EC and KEM one-time key counts.
func (m *KeysManager) GetPreKeyCount(ctx context.Context, accountUUID string, deviceID uint64) (*PreKeyState, error) {
	state, err := m.store.GetPreKeyCount(ctx, accountUUID, deviceID)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "failed to get pre-key count", err)
	}
	return state, nil
}

// StoreSignedPreKey persists a new signed EC pre-key for the given account and
// device, replacing any previously stored signed pre-key.
func (m *KeysManager) StoreSignedPreKey(ctx context.Context, accountUUID string, deviceID uint64, key *SignedPreKey) error {
	if key == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "signed pre-key must not be nil")
	}
	if err := m.store.StoreSignedPreKey(ctx, accountUUID, deviceID, key); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "failed to store signed pre-key", err)
	}
	return nil
}

// StoreKEMPreKeys persists a batch of KEM one-time pre-keys for the given
// account and device.
func (m *KeysManager) StoreKEMPreKeys(ctx context.Context, accountUUID string, deviceID uint64, preKeys []*KEMSignedPreKey) error {
	if len(preKeys) == 0 {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "KEM pre-keys must not be empty")
	}
	if err := m.store.StoreKEMPreKeys(ctx, accountUUID, deviceID, preKeys); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "failed to store KEM pre-keys", err)
	}
	return nil
}

// StoreKEMLastResortPreKey persists the last-resort KEM pre-key for the given
// account and device. This key is never consumed during session establishment
// and is returned only when no one-time KEM pre-keys remain.
func (m *KeysManager) StoreKEMLastResortPreKey(ctx context.Context, accountUUID string, deviceID uint64, preKey *KEMSignedPreKey) error {
	if preKey == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "KEM last-resort pre-key must not be nil")
	}
	if err := m.store.StoreKEMLastResortPreKey(ctx, accountUUID, deviceID, preKey); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "failed to store KEM last-resort pre-key", err)
	}
	return nil
}
