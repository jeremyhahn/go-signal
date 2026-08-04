package memory

import (
	"context"
	"sync"

	"github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// Compile-time interface satisfaction check.
var _ keys.PreKeyStore = (*MemoryPreKeyStore)(nil)

// MemoryPreKeyStore implements keys.PreKeyStore with in-memory storage.
type MemoryPreKeyStore struct {
	mu            sync.RWMutex
	ecKeys        map[deviceKey][]*keys.PreKey
	kemKeys       map[deviceKey][]*keys.KEMSignedPreKey
	signedKeys    map[deviceKey]*keys.SignedPreKey
	kemLastResort map[deviceKey]*keys.KEMSignedPreKey
}

// NewMemoryPreKeyStore creates a new in-memory pre-key store.
func NewMemoryPreKeyStore() *MemoryPreKeyStore {
	return &MemoryPreKeyStore{
		ecKeys:        make(map[deviceKey][]*keys.PreKey),
		kemKeys:       make(map[deviceKey][]*keys.KEMSignedPreKey),
		signedKeys:    make(map[deviceKey]*keys.SignedPreKey),
		kemLastResort: make(map[deviceKey]*keys.KEMSignedPreKey),
	}
}

// StoreECPreKeys persists a batch of EC one-time pre-keys for a device.
func (s *MemoryPreKeyStore) StoreECPreKeys(_ context.Context, uuid string, deviceID uint64, preKeys []*keys.PreKey) error {
	key := deviceKey{uuid: uuid, deviceID: deviceID}

	stored := make([]*keys.PreKey, len(preKeys))
	for i, pk := range preKeys {
		stored[i] = clonePreKey(pk)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.ecKeys[key] = append(s.ecKeys[key], stored...)
	return nil
}

// StoreKEMPreKeys persists a batch of KEM one-time pre-keys for a device.
func (s *MemoryPreKeyStore) StoreKEMPreKeys(_ context.Context, uuid string, deviceID uint64, preKeys []*keys.KEMSignedPreKey) error {
	key := deviceKey{uuid: uuid, deviceID: deviceID}

	stored := make([]*keys.KEMSignedPreKey, len(preKeys))
	for i, pk := range preKeys {
		stored[i] = cloneKEMPreKey(pk)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.kemKeys[key] = append(s.kemKeys[key], stored...)
	return nil
}

// StoreKEMLastResortPreKey persists the last-resort KEM pre-key for a device,
// replacing any previously stored one. The last-resort key is never consumed
// and must persist across session establishments.
func (s *MemoryPreKeyStore) StoreKEMLastResortPreKey(_ context.Context, uuid string, deviceID uint64, preKey *keys.KEMSignedPreKey) error {
	key := deviceKey{uuid: uuid, deviceID: deviceID}

	clone := cloneKEMPreKey(preKey)
	clone.IsLastResort = true

	s.mu.Lock()
	defer s.mu.Unlock()

	s.kemLastResort[key] = clone
	return nil
}

// StoreSignedPreKey persists the current signed pre-key for a device.
func (s *MemoryPreKeyStore) StoreSignedPreKey(_ context.Context, uuid string, deviceID uint64, signedPreKey *keys.SignedPreKey) error {
	key := deviceKey{uuid: uuid, deviceID: deviceID}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.signedKeys[key] = cloneSignedPreKey(signedPreKey)
	return nil
}

// TakeEC removes and returns one EC pre-key for a device.
func (s *MemoryPreKeyStore) TakeEC(_ context.Context, uuid string, deviceID uint64) (*keys.PreKey, error) {
	key := deviceKey{uuid: uuid, deviceID: deviceID}

	s.mu.Lock()
	defer s.mu.Unlock()

	ecKeys := s.ecKeys[key]
	if len(ecKeys) == 0 {
		return nil, errors.New(errors.ErrPreKeyNotAvailable, "no EC pre-keys available")
	}

	taken := ecKeys[0]
	s.ecKeys[key] = ecKeys[1:]

	return clonePreKey(taken), nil
}

// TakeKEM removes and returns one KEM pre-key for a device.
func (s *MemoryPreKeyStore) TakeKEM(_ context.Context, uuid string, deviceID uint64) (*keys.KEMSignedPreKey, error) {
	key := deviceKey{uuid: uuid, deviceID: deviceID}

	s.mu.Lock()
	defer s.mu.Unlock()

	kemKeys := s.kemKeys[key]
	if len(kemKeys) == 0 {
		return nil, errors.New(errors.ErrPreKeyNotAvailable, "no KEM pre-keys available")
	}

	taken := kemKeys[0]
	s.kemKeys[key] = kemKeys[1:]

	return cloneKEMPreKey(taken), nil
}

// GetKEMLastResortPreKey retrieves the last-resort KEM pre-key for a device
// without consuming it. Returns ErrPreKeyNotAvailable if no last-resort key is
// stored.
func (s *MemoryPreKeyStore) GetKEMLastResortPreKey(_ context.Context, uuid string, deviceID uint64) (*keys.KEMSignedPreKey, error) {
	key := deviceKey{uuid: uuid, deviceID: deviceID}

	s.mu.RLock()
	defer s.mu.RUnlock()

	pk, exists := s.kemLastResort[key]
	if !exists {
		return nil, errors.New(errors.ErrPreKeyNotAvailable, "no KEM last-resort pre-key available")
	}

	return cloneKEMPreKey(pk), nil
}

// GetSignedPreKey retrieves the current signed pre-key for a device.
func (s *MemoryPreKeyStore) GetSignedPreKey(_ context.Context, uuid string, deviceID uint64) (*keys.SignedPreKey, error) {
	key := deviceKey{uuid: uuid, deviceID: deviceID}

	s.mu.RLock()
	defer s.mu.RUnlock()

	spk, exists := s.signedKeys[key]
	if !exists {
		return nil, errors.New(errors.ErrPreKeyNotAvailable, "no signed pre-key available")
	}

	return cloneSignedPreKey(spk), nil
}

// GetPreKeyCount returns the count of remaining pre-keys for a device.
func (s *MemoryPreKeyStore) GetPreKeyCount(_ context.Context, uuid string, deviceID uint64) (*keys.PreKeyState, error) {
	key := deviceKey{uuid: uuid, deviceID: deviceID}

	s.mu.RLock()
	defer s.mu.RUnlock()

	_, hasLastResort := s.kemLastResort[key]

	return &keys.PreKeyState{
		ECCount:       len(s.ecKeys[key]),
		KEMCount:      len(s.kemKeys[key]),
		HasLastResort: hasLastResort,
	}, nil
}

// DeleteAllForDevice removes all pre-keys associated with a device.
func (s *MemoryPreKeyStore) DeleteAllForDevice(_ context.Context, uuid string, deviceID uint64) error {
	key := deviceKey{uuid: uuid, deviceID: deviceID}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.ecKeys, key)
	delete(s.kemKeys, key)
	delete(s.signedKeys, key)
	delete(s.kemLastResort, key)

	return nil
}

// DeleteAllForAccount removes all pre-keys associated with an account.
func (s *MemoryPreKeyStore) DeleteAllForAccount(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key := range s.ecKeys {
		if key.uuid == uuid {
			delete(s.ecKeys, key)
		}
	}
	for key := range s.kemKeys {
		if key.uuid == uuid {
			delete(s.kemKeys, key)
		}
	}
	for key := range s.signedKeys {
		if key.uuid == uuid {
			delete(s.signedKeys, key)
		}
	}
	for key := range s.kemLastResort {
		if key.uuid == uuid {
			delete(s.kemLastResort, key)
		}
	}

	return nil
}

// ListAccountUUIDs returns every UUID with pre-keys in any table.
func (s *MemoryPreKeyStore) ListAccountUUIDs(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]struct{})
	for k := range s.ecKeys {
		seen[k.uuid] = struct{}{}
	}
	for k := range s.kemKeys {
		seen[k.uuid] = struct{}{}
	}
	for k := range s.signedKeys {
		seen[k.uuid] = struct{}{}
	}
	for k := range s.kemLastResort {
		seen[k.uuid] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	return out, nil
}

// clonePreKey returns a deep copy of a PreKey.
func clonePreKey(pk *keys.PreKey) *keys.PreKey {
	return &keys.PreKey{
		KeyID:     pk.KeyID,
		PublicKey: cloneBytes(pk.PublicKey),
	}
}

// cloneSignedPreKey returns a deep copy of a SignedPreKey.
func cloneSignedPreKey(spk *keys.SignedPreKey) *keys.SignedPreKey {
	return &keys.SignedPreKey{
		KeyID:     spk.KeyID,
		PublicKey: cloneBytes(spk.PublicKey),
		Signature: cloneBytes(spk.Signature),
	}
}

// cloneKEMPreKey returns a deep copy of a KEMSignedPreKey.
func cloneKEMPreKey(pk *keys.KEMSignedPreKey) *keys.KEMSignedPreKey {
	return &keys.KEMSignedPreKey{
		KeyID:        pk.KeyID,
		PublicKey:    cloneBytes(pk.PublicKey),
		Signature:    cloneBytes(pk.Signature),
		IsLastResort: pk.IsLastResort,
	}
}
