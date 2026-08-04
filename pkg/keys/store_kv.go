package keys

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

const (
	kvSignedPrefix        = "signal/keys/signed/"
	kvECPrefix            = "signal/keys/ec/"
	kvKEMPrefix           = "signal/keys/kem/"
	kvKEMLastResortPrefix = "signal/keys/kem_last_resort/"
)

// PreKeyNotFoundError indicates the requested pre-key does not exist.
type PreKeyNotFoundError struct {
	UUID     string
	DeviceID uint64
	KeyType  string
}

func (e *PreKeyNotFoundError) Error() string {
	return e.KeyType + " pre-key not found for " + e.UUID +
		" device " + strconv.FormatUint(e.DeviceID, 10)
}

// KVPreKeyStore implements PreKeyStore using a KVClient backend.
type KVPreKeyStore struct {
	kv store.KVClient
}

// NewKVPreKeyStore returns a new KVPreKeyStore backed by the given KVClient.
func NewKVPreKeyStore(kv store.KVClient) *KVPreKeyStore {
	return &KVPreKeyStore{kv: kv}
}

// StoreECPreKeys persists a batch of EC one-time pre-keys for a device.
func (s *KVPreKeyStore) StoreECPreKeys(ctx context.Context, uuid string, deviceID uint64, preKeys []*PreKey) error {
	did := strconv.FormatUint(deviceID, 10)
	for _, pk := range preKeys {
		kid := strconv.FormatUint(pk.KeyID, 10)
		key := kvECPrefix + uuid + "/" + did + "/" + kid
		data, err := json.Marshal(pk)
		if err != nil {
			return err
		}
		if err := s.kv.Put(ctx, key, data); err != nil {
			return err
		}
	}
	return nil
}

// StoreKEMPreKeys persists a batch of KEM one-time pre-keys for a device.
func (s *KVPreKeyStore) StoreKEMPreKeys(ctx context.Context, uuid string, deviceID uint64, preKeys []*KEMSignedPreKey) error {
	did := strconv.FormatUint(deviceID, 10)
	for _, pk := range preKeys {
		kid := strconv.FormatUint(pk.KeyID, 10)
		key := kvKEMPrefix + uuid + "/" + did + "/" + kid
		data, err := json.Marshal(pk)
		if err != nil {
			return err
		}
		if err := s.kv.Put(ctx, key, data); err != nil {
			return err
		}
	}
	return nil
}

// StoreSignedPreKey persists the current signed pre-key for a device.
func (s *KVPreKeyStore) StoreSignedPreKey(ctx context.Context, uuid string, deviceID uint64, signedPreKey *SignedPreKey) error {
	did := strconv.FormatUint(deviceID, 10)
	key := kvSignedPrefix + uuid + "/" + did
	data, err := json.Marshal(signedPreKey)
	if err != nil {
		return err
	}
	return s.kv.Put(ctx, key, data)
}

// TakeEC removes and returns one EC pre-key for a device. The pre-key is
// claimed via an atomic DeleteIfPresent so a one-time pre-key is never handed
// to two concurrent callers (a forward-secrecy break). If another caller wins
// the race for a candidate key, the next candidate is tried.
func (s *KVPreKeyStore) TakeEC(ctx context.Context, uuid string, deviceID uint64) (*PreKey, error) {
	did := strconv.FormatUint(deviceID, 10)
	prefix := kvECPrefix + uuid + "/" + did + "/"
	keys, err := s.kv.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		data, err := s.kv.Get(ctx, k)
		if err != nil {
			var knf *store.KeyNotFoundError
			if errors.As(err, &knf) {
				continue // taken by a concurrent caller between List and Get
			}
			return nil, err
		}
		// Atomically claim this key. Only the caller that actually removed it
		// (removed == true) may return it; otherwise another caller already
		// consumed it, so move on.
		removed, err := s.kv.DeleteIfPresent(ctx, k)
		if err != nil {
			return nil, err
		}
		if !removed {
			continue
		}
		var pk PreKey
		if err := json.Unmarshal(data, &pk); err != nil {
			return nil, err
		}
		return &pk, nil
	}

	return nil, &PreKeyNotFoundError{UUID: uuid, DeviceID: deviceID, KeyType: "EC"}
}

// StoreKEMLastResortPreKey persists the last-resort KEM pre-key for a device.
// This key is stored under a separate prefix and is never deleted during session
// establishment.
func (s *KVPreKeyStore) StoreKEMLastResortPreKey(ctx context.Context, uuid string, deviceID uint64, preKey *KEMSignedPreKey) error {
	did := strconv.FormatUint(deviceID, 10)
	key := kvKEMLastResortPrefix + uuid + "/" + did
	lrKey := *preKey
	lrKey.IsLastResort = true
	data, err := json.Marshal(&lrKey)
	if err != nil {
		return err
	}
	return s.kv.Put(ctx, key, data)
}

// GetKEMLastResortPreKey retrieves the last-resort KEM pre-key for a device
// without consuming it. Returns PreKeyNotFoundError if none is stored.
func (s *KVPreKeyStore) GetKEMLastResortPreKey(ctx context.Context, uuid string, deviceID uint64) (*KEMSignedPreKey, error) {
	did := strconv.FormatUint(deviceID, 10)
	key := kvKEMLastResortPrefix + uuid + "/" + did
	data, err := s.kv.Get(ctx, key)
	if err != nil {
		var knf *store.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, &PreKeyNotFoundError{UUID: uuid, DeviceID: deviceID, KeyType: "KEM last-resort"}
		}
		return nil, err
	}
	var pk KEMSignedPreKey
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, err
	}
	pk.IsLastResort = true
	return &pk, nil
}

// TakeKEM removes and returns one KEM pre-key for a device. Like TakeEC it
// claims the key atomically via DeleteIfPresent so a one-time KEM pre-key is
// never consumed twice under concurrency.
func (s *KVPreKeyStore) TakeKEM(ctx context.Context, uuid string, deviceID uint64) (*KEMSignedPreKey, error) {
	did := strconv.FormatUint(deviceID, 10)
	prefix := kvKEMPrefix + uuid + "/" + did + "/"
	keys, err := s.kv.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		data, err := s.kv.Get(ctx, k)
		if err != nil {
			var knf *store.KeyNotFoundError
			if errors.As(err, &knf) {
				continue
			}
			return nil, err
		}
		removed, err := s.kv.DeleteIfPresent(ctx, k)
		if err != nil {
			return nil, err
		}
		if !removed {
			continue
		}
		var pk KEMSignedPreKey
		if err := json.Unmarshal(data, &pk); err != nil {
			return nil, err
		}
		return &pk, nil
	}

	return nil, &PreKeyNotFoundError{UUID: uuid, DeviceID: deviceID, KeyType: "KEM"}
}

// GetSignedPreKey retrieves the current signed pre-key for a device.
func (s *KVPreKeyStore) GetSignedPreKey(ctx context.Context, uuid string, deviceID uint64) (*SignedPreKey, error) {
	did := strconv.FormatUint(deviceID, 10)
	key := kvSignedPrefix + uuid + "/" + did
	data, err := s.kv.Get(ctx, key)
	if err != nil {
		var knf *store.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, &PreKeyNotFoundError{UUID: uuid, DeviceID: deviceID, KeyType: "signed"}
		}
		return nil, err
	}

	var spk SignedPreKey
	if err := json.Unmarshal(data, &spk); err != nil {
		return nil, err
	}
	return &spk, nil
}

// GetPreKeyCount returns the count of remaining EC and KEM pre-keys for a device,
// and whether a KEM last-resort pre-key is stored.
func (s *KVPreKeyStore) GetPreKeyCount(ctx context.Context, uuid string, deviceID uint64) (*PreKeyState, error) {
	did := strconv.FormatUint(deviceID, 10)

	ecKeys, err := s.kv.List(ctx, kvECPrefix+uuid+"/"+did+"/")
	if err != nil {
		return nil, err
	}

	kemKeys, err := s.kv.List(ctx, kvKEMPrefix+uuid+"/"+did+"/")
	if err != nil {
		return nil, err
	}

	// Check for last-resort key presence without fetching its full payload.
	lastResortKey := kvKEMLastResortPrefix + uuid + "/" + did
	_, lrErr := s.kv.Get(ctx, lastResortKey)
	hasLastResort := lrErr == nil

	return &PreKeyState{
		ECCount:       len(ecKeys),
		KEMCount:      len(kemKeys),
		HasLastResort: hasLastResort,
	}, nil
}

// DeleteAllForDevice removes all pre-keys associated with a device, including
// the KEM last-resort pre-key.
func (s *KVPreKeyStore) DeleteAllForDevice(ctx context.Context, uuid string, deviceID uint64) error {
	did := strconv.FormatUint(deviceID, 10)

	// Delete signed pre-key (not-found is benign for a device without one).
	if err := s.kv.Delete(ctx, kvSignedPrefix+uuid+"/"+did); err != nil {
		var knf *store.KeyNotFoundError
		if !errors.As(err, &knf) {
			return err
		}
	}

	// Delete KEM last-resort pre-key (not-found is benign for a device without one).
	if err := s.kv.Delete(ctx, kvKEMLastResortPrefix+uuid+"/"+did); err != nil {
		var knf *store.KeyNotFoundError
		if !errors.As(err, &knf) {
			return err
		}
	}

	// Delete all EC pre-keys.
	if err := s.deleteByPrefix(ctx, kvECPrefix+uuid+"/"+did+"/"); err != nil {
		return err
	}

	// Delete all KEM one-time pre-keys.
	return s.deleteByPrefix(ctx, kvKEMPrefix+uuid+"/"+did+"/")
}

// DeleteAllForAccount removes all pre-keys associated with an account, including
// KEM last-resort pre-keys.
func (s *KVPreKeyStore) DeleteAllForAccount(ctx context.Context, uuid string) error {
	// Delete all signed pre-keys for this account.
	if err := s.deleteByPrefix(ctx, kvSignedPrefix+uuid+"/"); err != nil {
		return err
	}

	// Delete all KEM last-resort pre-keys for this account.
	if err := s.deleteByPrefix(ctx, kvKEMLastResortPrefix+uuid+"/"); err != nil {
		return err
	}

	// Delete all EC one-time pre-keys for this account.
	if err := s.deleteByPrefix(ctx, kvECPrefix+uuid+"/"); err != nil {
		return err
	}

	// Delete all KEM one-time pre-keys for this account.
	return s.deleteByPrefix(ctx, kvKEMPrefix+uuid+"/")
}

// deleteByPrefix scans for keys with the given prefix and deletes them all.
func (s *KVPreKeyStore) deleteByPrefix(ctx context.Context, prefix string) error {
	keys, err := s.kv.List(ctx, prefix)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := s.kv.Delete(ctx, k); err != nil {
			var knf *store.KeyNotFoundError
			if errors.As(err, &knf) {
				continue
			}
			return err
		}
	}
	return nil
}

// ListAccountUUIDs returns every UUID with rows across the four
// pre-key prefixes. Keys follow `<prefix><uuid>/...`, so the UUID
// is the segment between the prefix and the next `/`.
func (s *KVPreKeyStore) ListAccountUUIDs(ctx context.Context) ([]string, error) {
	prefixes := []string{kvECPrefix, kvKEMPrefix, kvSignedPrefix, kvKEMLastResortPrefix}
	seen := make(map[string]struct{})
	for _, p := range prefixes {
		ks, err := s.kv.List(ctx, p)
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			rest := k[len(p):]
			slash := -1
			for i := 0; i < len(rest); i++ {
				if rest[i] == '/' {
					slash = i
					break
				}
			}
			if slash <= 0 {
				continue
			}
			seen[rest[:slash]] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	return out, nil
}
