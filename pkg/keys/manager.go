package keys

import (
	"context"
	"sync/atomic"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// DefaultLowKeyThreshold is the remaining-one-time-key count below which the
// low-key replenishment callback fires. Mirrors the conservative floor Java
// Signal-Server uses internally before clients are nudged to upload more.
const DefaultLowKeyThreshold = 25

// LowKeyEvent describes a device that has fallen below the configured
// replenishment floor on one or both one-time key types. signald wires this
// to a push-notification publisher; tests can wire a channel and assert.
type LowKeyEvent struct {
	AccountUUID  string
	DeviceID     uint64
	RemainingEC  int
	RemainingKEM int
	// LowEC is true when the EC one-time count is at or below the threshold.
	LowEC bool
	// LowKEM is true when the KEM one-time count is at or below the threshold.
	LowKEM bool
}

// LowKeyCallback receives a LowKeyEvent whenever a consuming bundle GET
// leaves a device below the configured threshold. Callbacks MUST NOT block
// the calling goroutine; the manager invokes them inline so callbacks are
// expected to dispatch their own goroutines or buffered channels.
type LowKeyCallback func(LowKeyEvent)

// KeysManager coordinates pre-key storage and retrieval operations. It wraps a
// PreKeyStore implementation and provides higher-level business logic for key
// management workflows.
type KeysManager struct {
	store           PreKeyStore
	lowKeyThreshold atomic.Int32
	lowKeyCallback  atomic.Pointer[LowKeyCallback]
}

// NewKeysManager creates a new KeysManager backed by the provided PreKeyStore.
// The low-key threshold defaults to DefaultLowKeyThreshold; no callback fires
// until SetLowKeyCallback registers one.
func NewKeysManager(store PreKeyStore) *KeysManager {
	m := &KeysManager{store: store}
	m.lowKeyThreshold.Store(DefaultLowKeyThreshold)
	return m
}

// SetLowKeyCallback registers fn as the replenishment-notification hook.
// Passing nil disables the callback. Safe to call concurrently; the new
// value takes effect for subsequent bundle GETs.
func (m *KeysManager) SetLowKeyCallback(fn LowKeyCallback) {
	if fn == nil {
		m.lowKeyCallback.Store(nil)
		return
	}
	m.lowKeyCallback.Store(&fn)
}

// SetLowKeyThreshold overrides the one-time key floor that triggers the
// callback. Values <= 0 reset to DefaultLowKeyThreshold.
func (m *KeysManager) SetLowKeyThreshold(n int) {
	if n <= 0 {
		n = DefaultLowKeyThreshold
	}
	m.lowKeyThreshold.Store(int32(n))
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

	m.maybeNotifyLowKeys(ctx, targetUUID, deviceID)
	return item, nil
}

// maybeNotifyLowKeys checks the remaining one-time key counts after a
// consuming bundle GET and invokes the registered LowKeyCallback if either
// the EC or KEM remaining count is at or below the threshold. The callback
// is invoked synchronously; callbacks that need to block (e.g. push
// notification IO) MUST spawn their own goroutine.
func (m *KeysManager) maybeNotifyLowKeys(ctx context.Context, targetUUID string, deviceID uint64) {
	cb := m.lowKeyCallback.Load()
	if cb == nil {
		return
	}
	state, err := m.store.GetPreKeyCount(ctx, targetUUID, deviceID)
	if err != nil {
		return
	}
	threshold := int(m.lowKeyThreshold.Load())
	lowEC := state.ECCount <= threshold
	lowKEM := state.KEMCount <= threshold
	if !lowEC && !lowKEM {
		return
	}
	(*cb)(LowKeyEvent{
		AccountUUID:  targetUUID,
		DeviceID:     deviceID,
		RemainingEC:  state.ECCount,
		RemainingKEM: state.KEMCount,
		LowEC:        lowEC,
		LowKEM:       lowKEM,
	})
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

// ListAccountUUIDs delegates to the underlying store. Used by the
// orphan pre-key sweeper.
func (m *KeysManager) ListAccountUUIDs(ctx context.Context) ([]string, error) {
	return m.store.ListAccountUUIDs(ctx)
}

// DeleteAllForAccount delegates to the underlying store. Used by the
// orphan pre-key sweeper to evict rows whose owning account is gone.
func (m *KeysManager) DeleteAllForAccount(ctx context.Context, accountUUID string) error {
	return m.store.DeleteAllForAccount(ctx, accountUUID)
}
