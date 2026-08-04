package qrdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// Key layout:
//
//	prekeys:ec:{uuid}:{device}:{keyID}          → JSON PreKey (one-time, consumed on take)
//	prekeys:kem:{uuid}:{device}:{keyID}         → JSON KEMSignedPreKey (one-time)
//	prekeys:kem-lastresort:{uuid}:{device}      → JSON KEMSignedPreKey
//	prekeys:signed:{uuid}:{device}              → JSON SignedPreKey (current)
//
// EC and KEM one-time keys are consumed by lexicographic scan + delete of
// the lowest remaining keyID — this matches Signal's lowest-ID-first
// semantics for one-time keys. A sync.Mutex is held per TakeEC/TakeKEM to
// prevent two concurrent takes from consuming the same key.

const (
	preKeyECPfx         = "prekeys:ec:"
	preKeyKEMPfx        = "prekeys:kem:"
	preKeyKEMLastResort = "prekeys:kem-lastresort:"
	preKeySignedPfx     = "prekeys:signed:"
	preKeyAccountAllPfx = "prekeys:"
)

var _ keys.PreKeyStore = (*PreKeyStore)(nil)

// PreKeyStore is a qrdb-backed implementation of keys.PreKeyStore.
type PreKeyStore struct {
	kv KVStore
	// Per-device take locks prevent two concurrent TakeEC / TakeKEM calls
	// from consuming the same key between list-and-delete.
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// NewPreKeyStore returns a PreKeyStore that persists to kv.
func NewPreKeyStore(kv KVStore) *PreKeyStore {
	return &PreKeyStore{kv: kv, locks: make(map[string]*sync.Mutex)}
}

// deviceLock returns (and lazily creates) a mutex scoped to a device. Two
// devices can Take concurrently; the same device serializes Takes.
func (s *PreKeyStore) deviceLock(uuid string, device uint64) *sync.Mutex {
	key := fmt.Sprintf("%s:%d", uuid, device)
	s.mu.Lock()
	defer s.mu.Unlock()
	lk, ok := s.locks[key]
	if !ok {
		lk = &sync.Mutex{}
		s.locks[key] = lk
	}
	return lk
}

func ecKey(uuid string, device, id uint64) string {
	return fmt.Sprintf("%s%s:%d:%020d", preKeyECPfx, uuid, device, id)
}
func kemKey(uuid string, device, id uint64) string {
	return fmt.Sprintf("%s%s:%d:%020d", preKeyKEMPfx, uuid, device, id)
}
func kemLastResortKey(uuid string, device uint64) string {
	return fmt.Sprintf("%s%s:%d", preKeyKEMLastResort, uuid, device)
}
func signedKey(uuid string, device uint64) string {
	return fmt.Sprintf("%s%s:%d", preKeySignedPfx, uuid, device)
}
func ecDevicePrefix(uuid string, device uint64) string {
	return fmt.Sprintf("%s%s:%d:", preKeyECPfx, uuid, device)
}
func kemDevicePrefix(uuid string, device uint64) string {
	return fmt.Sprintf("%s%s:%d:", preKeyKEMPfx, uuid, device)
}

// accountAllKeys scans every key-store prefix (ec, kem, kem-lastresort,
// signed) for the given account UUID. Used by DeleteAllForAccount /
// DeleteAllForDevice to clean up across kinds without needing a unified
// namespace key.
func (s *PreKeyStore) accountAllKeys(ctx context.Context, accountUUID string, device uint64, deviceOnly bool) ([]string, error) {
	prefixes := []string{preKeyECPfx, preKeyKEMPfx, preKeyKEMLastResort, preKeySignedPfx}
	out := make([]string, 0)
	for _, p := range prefixes {
		var scanPrefix string
		if deviceOnly {
			scanPrefix = fmt.Sprintf("%s%s:%d", p, accountUUID, device)
		} else {
			scanPrefix = fmt.Sprintf("%s%s:", p, accountUUID)
		}
		keys, err := s.kv.List(ctx, scanPrefix)
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: list", err)
		}
		out = append(out, keys...)
	}
	return out, nil
}

// StoreECPreKeys replaces the current batch of EC one-time pre-keys for a
// device. Existing EC one-time keys are removed first so the store
// reflects the caller's intent exactly.
func (s *PreKeyStore) StoreECPreKeys(ctx context.Context, uuid string, deviceID uint64, preKeys []*keys.PreKey) error {
	// Clear existing.
	existing, err := s.kv.List(ctx, ecDevicePrefix(uuid, deviceID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: list ec", err)
	}
	for _, k := range existing {
		if err := s.kv.Delete(ctx, k); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: delete ec", err)
		}
	}

	for _, p := range preKeys {
		if p == nil {
			continue
		}
		data, err := json.Marshal(p)
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: marshal ec", err)
		}
		if err := s.kv.Put(ctx, ecKey(uuid, deviceID, p.KeyID), data); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: put ec", err)
		}
	}
	return nil
}

// StoreKEMPreKeys replaces the KEM one-time pre-key batch for a device.
func (s *PreKeyStore) StoreKEMPreKeys(ctx context.Context, uuid string, deviceID uint64, preKeys []*keys.KEMSignedPreKey) error {
	existing, err := s.kv.List(ctx, kemDevicePrefix(uuid, deviceID))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: list kem", err)
	}
	for _, k := range existing {
		if err := s.kv.Delete(ctx, k); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: delete kem", err)
		}
	}
	for _, p := range preKeys {
		if p == nil {
			continue
		}
		data, err := json.Marshal(p)
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: marshal kem", err)
		}
		if err := s.kv.Put(ctx, kemKey(uuid, deviceID, p.KeyID), data); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: put kem", err)
		}
	}
	return nil
}

// StoreKEMLastResortPreKey stores or replaces the last-resort KEM key.
func (s *PreKeyStore) StoreKEMLastResortPreKey(ctx context.Context, uuid string, deviceID uint64, preKey *keys.KEMSignedPreKey) error {
	if preKey == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb prekeys: nil last-resort key")
	}
	data, err := json.Marshal(preKey)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: marshal last-resort", err)
	}
	if err := s.kv.Put(ctx, kemLastResortKey(uuid, deviceID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: put last-resort", err)
	}
	return nil
}

// StoreSignedPreKey stores or replaces the current signed pre-key.
func (s *PreKeyStore) StoreSignedPreKey(ctx context.Context, uuid string, deviceID uint64, signedPreKey *keys.SignedPreKey) error {
	if signedPreKey == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb prekeys: nil signed pre-key")
	}
	data, err := json.Marshal(signedPreKey)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: marshal signed", err)
	}
	if err := s.kv.Put(ctx, signedKey(uuid, deviceID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: put signed", err)
	}
	return nil
}

// TakeEC removes and returns one EC pre-key. Returns ErrPreKeyNotAvailable
// when the device has no one-time EC keys remaining.
func (s *PreKeyStore) TakeEC(ctx context.Context, uuid string, deviceID uint64) (*keys.PreKey, error) {
	lk := s.deviceLock(uuid, deviceID)
	lk.Lock()
	defer lk.Unlock()

	lst, err := s.kv.List(ctx, ecDevicePrefix(uuid, deviceID))
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: list ec", err)
	}
	if len(lst) == 0 {
		return nil, signalerrors.New(signalerrors.ErrPreKeyNotAvailable, "no EC pre-keys available")
	}
	firstKey := lst[0]
	data, err := getOrNotFound(ctx, s.kv, firstKey)
	if errors.Is(err, ErrNotFound) {
		return nil, signalerrors.New(signalerrors.ErrPreKeyNotAvailable, "no EC pre-keys available")
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: get ec", err)
	}
	var pk keys.PreKey
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: unmarshal ec", err)
	}
	if err := s.kv.Delete(ctx, firstKey); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: delete ec", err)
	}
	return &pk, nil
}

// TakeKEM removes and returns one KEM one-time pre-key. Returns
// ErrPreKeyNotAvailable when exhausted. Callers must fall back to
// GetKEMLastResortPreKey on that error.
func (s *PreKeyStore) TakeKEM(ctx context.Context, uuid string, deviceID uint64) (*keys.KEMSignedPreKey, error) {
	lk := s.deviceLock(uuid, deviceID)
	lk.Lock()
	defer lk.Unlock()

	lst, err := s.kv.List(ctx, kemDevicePrefix(uuid, deviceID))
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: list kem", err)
	}
	if len(lst) == 0 {
		return nil, signalerrors.New(signalerrors.ErrPreKeyNotAvailable, "no KEM pre-keys available")
	}
	firstKey := lst[0]
	data, err := getOrNotFound(ctx, s.kv, firstKey)
	if errors.Is(err, ErrNotFound) {
		return nil, signalerrors.New(signalerrors.ErrPreKeyNotAvailable, "no KEM pre-keys available")
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: get kem", err)
	}
	var pk keys.KEMSignedPreKey
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: unmarshal kem", err)
	}
	if err := s.kv.Delete(ctx, firstKey); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: delete kem", err)
	}
	return &pk, nil
}

// GetKEMLastResortPreKey returns the last-resort key without consuming it.
func (s *PreKeyStore) GetKEMLastResortPreKey(ctx context.Context, uuid string, deviceID uint64) (*keys.KEMSignedPreKey, error) {
	data, err := getOrNotFound(ctx, s.kv, kemLastResortKey(uuid, deviceID))
	if errors.Is(err, ErrNotFound) {
		return nil, signalerrors.New(signalerrors.ErrPreKeyNotAvailable, "no last-resort key for "+uuid+" device "+strconv.FormatUint(deviceID, 10))
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: get last-resort", err)
	}
	var pk keys.KEMSignedPreKey
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: unmarshal last-resort", err)
	}
	return &pk, nil
}

// GetSignedPreKey returns the current signed pre-key.
func (s *PreKeyStore) GetSignedPreKey(ctx context.Context, uuid string, deviceID uint64) (*keys.SignedPreKey, error) {
	data, err := getOrNotFound(ctx, s.kv, signedKey(uuid, deviceID))
	if errors.Is(err, ErrNotFound) {
		return nil, signalerrors.New(signalerrors.ErrPreKeyNotAvailable, "no signed pre-key for "+uuid+" device "+strconv.FormatUint(deviceID, 10))
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: get signed", err)
	}
	var spk keys.SignedPreKey
	if err := json.Unmarshal(data, &spk); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: unmarshal signed", err)
	}
	return &spk, nil
}

// GetPreKeyCount returns the current counts for EC / KEM / last-resort.
func (s *PreKeyStore) GetPreKeyCount(ctx context.Context, uuid string, deviceID uint64) (*keys.PreKeyState, error) {
	ec, err := s.kv.List(ctx, ecDevicePrefix(uuid, deviceID))
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: list ec", err)
	}
	kem, err := s.kv.List(ctx, kemDevicePrefix(uuid, deviceID))
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: list kem", err)
	}
	hasLR, err := s.kv.Exists(ctx, kemLastResortKey(uuid, deviceID))
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: exists last-resort", err)
	}
	return &keys.PreKeyState{ECCount: len(ec), KEMCount: len(kem), HasLastResort: hasLR}, nil
}

// DeleteAllForDevice removes every key owned by the (uuid, device) pair.
func (s *PreKeyStore) DeleteAllForDevice(ctx context.Context, uuid string, deviceID uint64) error {
	all, err := s.accountAllKeys(ctx, uuid, deviceID, true)
	if err != nil {
		return err
	}
	for _, k := range all {
		if err := s.kv.Delete(ctx, k); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: delete", err)
		}
	}
	return nil
}

// DeleteAllForAccount removes every key owned by any device of the account.
func (s *PreKeyStore) DeleteAllForAccount(ctx context.Context, uuid string) error {
	all, err := s.accountAllKeys(ctx, uuid, 0, false)
	if err != nil {
		return err
	}
	for _, k := range all {
		if err := s.kv.Delete(ctx, k); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: delete", err)
		}
	}
	return nil
}

// ListAccountUUIDs returns every UUID that appears as the owner of
// any pre-key row across the EC, KEM, KEM-last-resort, or signed
// prefixes. Keys follow the layout `<prefix><uuid>:...`, so the UUID
// is the second segment after the prefix.
func (s *PreKeyStore) ListAccountUUIDs(ctx context.Context) ([]string, error) {
	prefixes := []string{preKeyECPfx, preKeyKEMPfx, preKeyKEMLastResort, preKeySignedPfx}
	seen := make(map[string]struct{})
	for _, p := range prefixes {
		ks, err := s.kv.List(ctx, p)
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb prekeys: list "+strconv.Quote(p), err)
		}
		for _, k := range ks {
			rest := k[len(p):]
			colon := -1
			for i := 0; i < len(rest); i++ {
				if rest[i] == ':' {
					colon = i
					break
				}
			}
			if colon <= 0 {
				continue
			}
			seen[rest[:colon]] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	return out, nil
}
