package keys

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// mockPreKeyStore is an in-memory PreKeyStore for testing.
type mockPreKeyStore struct {
	mu            sync.Mutex
	ecKeys        map[string][]*PreKey          // key: "uuid:deviceID"
	kemKeys       map[string][]*KEMSignedPreKey // key: "uuid:deviceID"
	kemLastResort map[string]*KEMSignedPreKey   // key: "uuid:deviceID"
	signedKeys    map[string]*SignedPreKey      // key: "uuid:deviceID"

	// Error injection hooks
	storeECErr            error
	storeKEMErr           error
	storeKEMLastResortErr error
	storeSignedErr        error
	takeECErr             error
	takeKEMErr            error
	getKEMLastResortErr   error
	getSignedErr          error
	getCountErr           error
	deleteDevErr          error
	deleteAccErr          error
}

func newMockPreKeyStore() *mockPreKeyStore {
	return &mockPreKeyStore{
		ecKeys:        make(map[string][]*PreKey),
		kemKeys:       make(map[string][]*KEMSignedPreKey),
		kemLastResort: make(map[string]*KEMSignedPreKey),
		signedKeys:    make(map[string]*SignedPreKey),
	}
}

func deviceKey(uuid string, deviceID uint64) string {
	return fmt.Sprintf("%s:%d", uuid, deviceID)
}

func (s *mockPreKeyStore) StoreECPreKeys(_ context.Context, uuid string, deviceID uint64, preKeys []*PreKey) error {
	if s.storeECErr != nil {
		return s.storeECErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := deviceKey(uuid, deviceID)
	s.ecKeys[k] = append(s.ecKeys[k], preKeys...)
	return nil
}

func (s *mockPreKeyStore) StoreKEMPreKeys(_ context.Context, uuid string, deviceID uint64, preKeys []*KEMSignedPreKey) error {
	if s.storeKEMErr != nil {
		return s.storeKEMErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := deviceKey(uuid, deviceID)
	s.kemKeys[k] = append(s.kemKeys[k], preKeys...)
	return nil
}

func (s *mockPreKeyStore) StoreKEMLastResortPreKey(_ context.Context, uuid string, deviceID uint64, preKey *KEMSignedPreKey) error {
	if s.storeKEMLastResortErr != nil {
		return s.storeKEMLastResortErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *preKey
	clone.IsLastResort = true
	s.kemLastResort[deviceKey(uuid, deviceID)] = &clone
	return nil
}

func (s *mockPreKeyStore) GetKEMLastResortPreKey(_ context.Context, uuid string, deviceID uint64) (*KEMSignedPreKey, error) {
	if s.getKEMLastResortErr != nil {
		return nil, s.getKEMLastResortErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pk, ok := s.kemLastResort[deviceKey(uuid, deviceID)]
	if !ok {
		return nil, errors.New("no KEM last-resort pre-key available")
	}
	return pk, nil
}

func (s *mockPreKeyStore) StoreSignedPreKey(_ context.Context, uuid string, deviceID uint64, signedPreKey *SignedPreKey) error {
	if s.storeSignedErr != nil {
		return s.storeSignedErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signedKeys[deviceKey(uuid, deviceID)] = signedPreKey
	return nil
}

func (s *mockPreKeyStore) TakeEC(_ context.Context, uuid string, deviceID uint64) (*PreKey, error) {
	if s.takeECErr != nil {
		return nil, s.takeECErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := deviceKey(uuid, deviceID)
	keys := s.ecKeys[k]
	if len(keys) == 0 {
		return nil, errors.New("no EC pre-keys available")
	}
	pk := keys[0]
	s.ecKeys[k] = keys[1:]
	return pk, nil
}

func (s *mockPreKeyStore) TakeKEM(_ context.Context, uuid string, deviceID uint64) (*KEMSignedPreKey, error) {
	if s.takeKEMErr != nil {
		return nil, s.takeKEMErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := deviceKey(uuid, deviceID)
	keys := s.kemKeys[k]
	if len(keys) == 0 {
		return nil, errors.New("no KEM pre-keys available")
	}
	pk := keys[0]
	s.kemKeys[k] = keys[1:]
	return pk, nil
}

func (s *mockPreKeyStore) GetSignedPreKey(_ context.Context, uuid string, deviceID uint64) (*SignedPreKey, error) {
	if s.getSignedErr != nil {
		return nil, s.getSignedErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	spk, ok := s.signedKeys[deviceKey(uuid, deviceID)]
	if !ok {
		return nil, errors.New("signed pre-key not found")
	}
	return spk, nil
}

func (s *mockPreKeyStore) GetPreKeyCount(_ context.Context, uuid string, deviceID uint64) (*PreKeyState, error) {
	if s.getCountErr != nil {
		return nil, s.getCountErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := deviceKey(uuid, deviceID)
	_, hasLastResort := s.kemLastResort[k]
	return &PreKeyState{
		ECCount:       len(s.ecKeys[k]),
		KEMCount:      len(s.kemKeys[k]),
		HasLastResort: hasLastResort,
	}, nil
}

func (s *mockPreKeyStore) DeleteAllForDevice(_ context.Context, uuid string, deviceID uint64) error {
	if s.deleteDevErr != nil {
		return s.deleteDevErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := deviceKey(uuid, deviceID)
	delete(s.ecKeys, k)
	delete(s.kemKeys, k)
	delete(s.kemLastResort, k)
	delete(s.signedKeys, k)
	return nil
}

func (s *mockPreKeyStore) DeleteAllForAccount(_ context.Context, uuid string) error {
	if s.deleteAccErr != nil {
		return s.deleteAccErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.ecKeys {
		if len(k) > len(uuid) && k[:len(uuid)] == uuid {
			delete(s.ecKeys, k)
		}
	}
	for k := range s.kemKeys {
		if len(k) > len(uuid) && k[:len(uuid)] == uuid {
			delete(s.kemKeys, k)
		}
	}
	for k := range s.kemLastResort {
		if len(k) > len(uuid) && k[:len(uuid)] == uuid {
			delete(s.kemLastResort, k)
		}
	}
	for k := range s.signedKeys {
		if len(k) > len(uuid) && k[:len(uuid)] == uuid {
			delete(s.signedKeys, k)
		}
	}
	return nil
}

func (s *mockPreKeyStore) ListAccountUUIDs(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]struct{})
	collect := func(k string) {
		for i := 0; i < len(k); i++ {
			if k[i] == '/' {
				if i > 0 {
					seen[k[:i]] = struct{}{}
				}
				return
			}
		}
		if k != "" {
			seen[k] = struct{}{}
		}
	}
	for k := range s.ecKeys {
		collect(k)
	}
	for k := range s.kemKeys {
		collect(k)
	}
	for k := range s.signedKeys {
		collect(k)
	}
	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	return out, nil
}

// --- NewKeysManager tests ---

func TestNewKeysManager_ReturnsNonNil(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	if mgr == nil {
		t.Fatal("expected non-nil KeysManager")
	}
}

func TestNewKeysManager_StoresReference(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	if mgr.store != store {
		t.Fatal("expected manager to hold reference to provided store")
	}
}

// --- StoreKeys tests ---

func TestStoreKeys_NilRequest(t *testing.T) {
	mgr := NewKeysManager(newMockPreKeyStore())
	err := mgr.StoreKeys(context.Background(), "uuid-1", 1, nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInvalidArgument {
		t.Errorf("expected ErrInvalidArgument, got %d", sigErr.Code)
	}
}

func TestStoreKeys_EmptyRequest(t *testing.T) {
	mgr := NewKeysManager(newMockPreKeyStore())
	err := mgr.StoreKeys(context.Background(), "uuid-1", 1, &SetKeysRequest{})
	if err != nil {
		t.Fatalf("expected no error for empty request, got %v", err)
	}
}

func TestStoreKeys_AllKeyTypes(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	req := &SetKeysRequest{
		PreKeys:      []*PreKey{{KeyID: 1, PublicKey: []byte{0x01}}},
		SignedPreKey: &SignedPreKey{KeyID: 2, PublicKey: []byte{0x02}, Signature: []byte{0x03}},
		KEMPreKeys:   []*KEMSignedPreKey{{KeyID: 3, PublicKey: []byte{0x04}, Signature: []byte{0x05}}},
	}
	err := mgr.StoreKeys(context.Background(), "uuid-1", 1, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	k := deviceKey("uuid-1", 1)
	if len(store.ecKeys[k]) != 1 {
		t.Errorf("expected 1 EC key, got %d", len(store.ecKeys[k]))
	}
	if len(store.kemKeys[k]) != 1 {
		t.Errorf("expected 1 KEM key, got %d", len(store.kemKeys[k]))
	}
	if store.signedKeys[k] == nil {
		t.Error("expected signed pre-key to be stored")
	}
}

func TestStoreKeys_OnlyECKeys(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	req := &SetKeysRequest{
		PreKeys: []*PreKey{{KeyID: 1, PublicKey: []byte{0x01}}, {KeyID: 2, PublicKey: []byte{0x02}}},
	}
	err := mgr.StoreKeys(context.Background(), "uuid-1", 1, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	k := deviceKey("uuid-1", 1)
	if len(store.ecKeys[k]) != 2 {
		t.Errorf("expected 2 EC keys, got %d", len(store.ecKeys[k]))
	}
}

func TestStoreKeys_OnlySignedPreKey(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	req := &SetKeysRequest{
		SignedPreKey: &SignedPreKey{KeyID: 10, PublicKey: []byte{0xAA}, Signature: []byte{0xBB}},
	}
	err := mgr.StoreKeys(context.Background(), "uuid-2", 2, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.signedKeys[deviceKey("uuid-2", 2)] == nil {
		t.Error("expected signed pre-key to be stored")
	}
}

func TestStoreKeys_OnlyKEMKeys(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	req := &SetKeysRequest{
		KEMPreKeys: []*KEMSignedPreKey{{KeyID: 5, PublicKey: []byte{0x55}, Signature: []byte{0x66}}},
	}
	err := mgr.StoreKeys(context.Background(), "uuid-3", 3, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	k := deviceKey("uuid-3", 3)
	if len(store.kemKeys[k]) != 1 {
		t.Errorf("expected 1 KEM key, got %d", len(store.kemKeys[k]))
	}
}

func TestStoreKeys_ECStoreError(t *testing.T) {
	store := newMockPreKeyStore()
	store.storeECErr = errors.New("ec storage failure")
	mgr := NewKeysManager(store)
	req := &SetKeysRequest{
		PreKeys: []*PreKey{{KeyID: 1, PublicKey: []byte{0x01}}},
	}
	err := mgr.StoreKeys(context.Background(), "uuid-1", 1, req)
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
	if sigErr.Cause == nil {
		t.Error("expected wrapped cause")
	}
}

func TestStoreKeys_SignedPreKeyStoreError(t *testing.T) {
	store := newMockPreKeyStore()
	store.storeSignedErr = errors.New("signed storage failure")
	mgr := NewKeysManager(store)
	req := &SetKeysRequest{
		SignedPreKey: &SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}},
	}
	err := mgr.StoreKeys(context.Background(), "uuid-1", 1, req)
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
}

func TestStoreKeys_KEMStoreError(t *testing.T) {
	store := newMockPreKeyStore()
	store.storeKEMErr = errors.New("kem storage failure")
	mgr := NewKeysManager(store)
	req := &SetKeysRequest{
		KEMPreKeys: []*KEMSignedPreKey{{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}},
	}
	err := mgr.StoreKeys(context.Background(), "uuid-1", 1, req)
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
}

// --- GetPreKeys tests ---

func TestGetPreKeys_Success_AllKeys(t *testing.T) {
	store := newMockPreKeyStore()
	k := deviceKey("target-uuid", 1)
	store.signedKeys[k] = &SignedPreKey{KeyID: 10, PublicKey: []byte{0x10}, Signature: []byte{0x11}}
	store.ecKeys[k] = []*PreKey{{KeyID: 20, PublicKey: []byte{0x20}}}
	store.kemKeys[k] = []*KEMSignedPreKey{{KeyID: 30, PublicKey: []byte{0x30}, Signature: []byte{0x31}}}

	mgr := NewKeysManager(store)
	item, err := mgr.GetPreKeys(context.Background(), "target-uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if item.DeviceID != 1 {
		t.Errorf("expected DeviceID 1, got %d", item.DeviceID)
	}
	if item.SignedPreKey == nil {
		t.Fatal("expected non-nil SignedPreKey")
	}
	if item.SignedPreKey.KeyID != 10 {
		t.Errorf("expected SignedPreKey.KeyID 10, got %d", item.SignedPreKey.KeyID)
	}
	if item.PreKey == nil {
		t.Fatal("expected non-nil PreKey")
	}
	if item.PreKey.KeyID != 20 {
		t.Errorf("expected PreKey.KeyID 20, got %d", item.PreKey.KeyID)
	}
	if item.KEMPreKey == nil {
		t.Fatal("expected non-nil KEMPreKey")
	}
	if item.KEMPreKey.KeyID != 30 {
		t.Errorf("expected KEMPreKey.KeyID 30, got %d", item.KEMPreKey.KeyID)
	}
}

func TestGetPreKeys_NoOneTimeKeys(t *testing.T) {
	store := newMockPreKeyStore()
	k := deviceKey("target-uuid", 1)
	store.signedKeys[k] = &SignedPreKey{KeyID: 10, PublicKey: []byte{0x10}, Signature: []byte{0x11}}

	mgr := NewKeysManager(store)
	item, err := mgr.GetPreKeys(context.Background(), "target-uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if item.SignedPreKey == nil {
		t.Fatal("expected non-nil SignedPreKey")
	}
	if item.PreKey != nil {
		t.Errorf("expected nil PreKey when none available, got %v", item.PreKey)
	}
	if item.KEMPreKey != nil {
		t.Errorf("expected nil KEMPreKey when none available, got %v", item.KEMPreKey)
	}
}

func TestGetPreKeys_SignedPreKeyError(t *testing.T) {
	store := newMockPreKeyStore()
	store.getSignedErr = errors.New("storage failure")
	mgr := NewKeysManager(store)

	_, err := mgr.GetPreKeys(context.Background(), "target-uuid", 1)
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrPreKeyNotAvailable {
		t.Errorf("expected ErrPreKeyNotAvailable, got %d", sigErr.Code)
	}
}

func TestGetPreKeys_ConsumesOneTimeKeys(t *testing.T) {
	store := newMockPreKeyStore()
	k := deviceKey("uuid", 1)
	store.signedKeys[k] = &SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}
	store.ecKeys[k] = []*PreKey{
		{KeyID: 10, PublicKey: []byte{0x10}},
		{KeyID: 11, PublicKey: []byte{0x11}},
	}

	mgr := NewKeysManager(store)

	item1, err := mgr.GetPreKeys(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if item1.PreKey.KeyID != 10 {
		t.Errorf("expected first EC key ID 10, got %d", item1.PreKey.KeyID)
	}

	item2, err := mgr.GetPreKeys(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if item2.PreKey.KeyID != 11 {
		t.Errorf("expected second EC key ID 11, got %d", item2.PreKey.KeyID)
	}

	// Third call - no more EC keys
	item3, err := mgr.GetPreKeys(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if item3.PreKey != nil {
		t.Errorf("expected nil PreKey after exhaustion, got %v", item3.PreKey)
	}
}

func TestGetPreKeys_TakeECError_NonFatal(t *testing.T) {
	store := newMockPreKeyStore()
	k := deviceKey("uuid", 1)
	store.signedKeys[k] = &SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}
	store.takeECErr = errors.New("ec take error")

	mgr := NewKeysManager(store)
	item, err := mgr.GetPreKeys(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("expected no error (EC failure is non-fatal), got %v", err)
	}
	if item.PreKey != nil {
		t.Error("expected nil PreKey on TakeEC error")
	}
}

func TestGetPreKeys_TakeKEMError_NonFatal(t *testing.T) {
	store := newMockPreKeyStore()
	k := deviceKey("uuid", 1)
	store.signedKeys[k] = &SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}
	store.takeKEMErr = errors.New("kem take error")

	mgr := NewKeysManager(store)
	item, err := mgr.GetPreKeys(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("expected no error (KEM failure is non-fatal), got %v", err)
	}
	if item.KEMPreKey != nil {
		t.Error("expected nil KEMPreKey on TakeKEM error with no last-resort key")
	}
}

func TestGetPreKeys_KEM_FallsBackToLastResort(t *testing.T) {
	// When one-time KEM keys are exhausted, the last-resort key must be returned
	// without being consumed.
	store := newMockPreKeyStore()
	k := deviceKey("uuid", 1)
	store.signedKeys[k] = &SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}
	// No one-time KEM keys; only a last-resort key.
	store.kemLastResort[k] = &KEMSignedPreKey{KeyID: 99, PublicKey: []byte{0x99}, Signature: []byte{0x98}, IsLastResort: true}

	mgr := NewKeysManager(store)

	// First call returns last-resort key.
	item, err := mgr.GetPreKeys(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if item.KEMPreKey == nil {
		t.Fatal("expected KEMPreKey (last-resort) to be returned")
	}
	if item.KEMPreKey.KeyID != 99 {
		t.Errorf("expected last-resort KeyID 99, got %d", item.KEMPreKey.KeyID)
	}
	if !item.KEMPreKey.IsLastResort {
		t.Error("expected IsLastResort=true on returned last-resort key")
	}

	// Second call must also return the same last-resort key (not consumed).
	item2, err := mgr.GetPreKeys(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if item2.KEMPreKey == nil {
		t.Fatal("expected last-resort key still available on second call")
	}
	if item2.KEMPreKey.KeyID != 99 {
		t.Errorf("expected last-resort KeyID 99 on second call, got %d", item2.KEMPreKey.KeyID)
	}
}

func TestGetPreKeys_KEM_UsesOneTimeBeforeLastResort(t *testing.T) {
	// One-time KEM keys must be consumed before the last-resort key is returned.
	store := newMockPreKeyStore()
	k := deviceKey("uuid", 1)
	store.signedKeys[k] = &SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}
	store.kemKeys[k] = []*KEMSignedPreKey{{KeyID: 10, PublicKey: []byte{0x10}, Signature: []byte{0x11}}}
	store.kemLastResort[k] = &KEMSignedPreKey{KeyID: 99, PublicKey: []byte{0x99}, Signature: []byte{0x98}, IsLastResort: true}

	mgr := NewKeysManager(store)

	// First call: consumes the one-time key.
	item, err := mgr.GetPreKeys(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if item.KEMPreKey == nil || item.KEMPreKey.KeyID != 10 {
		t.Errorf("expected one-time KEM KeyID 10, got %v", item.KEMPreKey)
	}

	// Second call: one-time keys exhausted, must fall back to last-resort.
	item2, err := mgr.GetPreKeys(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if item2.KEMPreKey == nil || item2.KEMPreKey.KeyID != 99 {
		t.Errorf("expected last-resort KeyID 99, got %v", item2.KEMPreKey)
	}
}

func TestGetPreKeys_KEM_LastResortNotReturnedWhenOneTimeAvailable(t *testing.T) {
	store := newMockPreKeyStore()
	k := deviceKey("uuid", 1)
	store.signedKeys[k] = &SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}
	store.kemKeys[k] = []*KEMSignedPreKey{{KeyID: 5, PublicKey: []byte{0x05}, Signature: []byte{0x06}}}
	store.kemLastResort[k] = &KEMSignedPreKey{KeyID: 99, PublicKey: []byte{0x99}, Signature: []byte{0x98}, IsLastResort: true}

	mgr := NewKeysManager(store)

	item, err := mgr.GetPreKeys(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if item.KEMPreKey == nil || item.KEMPreKey.KeyID != 5 {
		t.Errorf("expected one-time KEM KeyID 5, got %v", item.KEMPreKey)
	}
	// Ensure it's not the last-resort key.
	if item.KEMPreKey.IsLastResort {
		t.Error("expected IsLastResort=false when one-time keys are available")
	}
}

// --- GetPreKeyCount tests ---

func TestGetPreKeyCount_Success(t *testing.T) {
	store := newMockPreKeyStore()
	k := deviceKey("uuid", 1)
	store.ecKeys[k] = []*PreKey{{KeyID: 1}, {KeyID: 2}, {KeyID: 3}}
	store.kemKeys[k] = []*KEMSignedPreKey{{KeyID: 10}, {KeyID: 11}}

	mgr := NewKeysManager(store)
	state, err := mgr.GetPreKeyCount(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != 3 {
		t.Errorf("expected ECCount 3, got %d", state.ECCount)
	}
	if state.KEMCount != 2 {
		t.Errorf("expected KEMCount 2, got %d", state.KEMCount)
	}
}

func TestGetPreKeyCount_ZeroCounts(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	state, err := mgr.GetPreKeyCount(context.Background(), "uuid", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.ECCount != 0 {
		t.Errorf("expected ECCount 0, got %d", state.ECCount)
	}
	if state.KEMCount != 0 {
		t.Errorf("expected KEMCount 0, got %d", state.KEMCount)
	}
}

func TestGetPreKeyCount_StoreError(t *testing.T) {
	store := newMockPreKeyStore()
	store.getCountErr = errors.New("count failure")
	mgr := NewKeysManager(store)

	_, err := mgr.GetPreKeyCount(context.Background(), "uuid", 1)
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
}

// --- StoreSignedPreKey tests ---

func TestStoreSignedPreKey_Success(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	key := &SignedPreKey{KeyID: 42, PublicKey: []byte{0x42}, Signature: []byte{0x43}}

	err := mgr.StoreSignedPreKey(context.Background(), "uuid", 1, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stored := store.signedKeys[deviceKey("uuid", 1)]
	if stored == nil {
		t.Fatal("expected signed pre-key to be stored")
		return
	}
	if stored.KeyID != 42 {
		t.Errorf("expected KeyID 42, got %d", stored.KeyID)
	}
}

func TestStoreSignedPreKey_NilKey(t *testing.T) {
	mgr := NewKeysManager(newMockPreKeyStore())
	err := mgr.StoreSignedPreKey(context.Background(), "uuid", 1, nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInvalidArgument {
		t.Errorf("expected ErrInvalidArgument, got %d", sigErr.Code)
	}
}

func TestStoreSignedPreKey_StoreError(t *testing.T) {
	store := newMockPreKeyStore()
	store.storeSignedErr = errors.New("signed store failure")
	mgr := NewKeysManager(store)
	key := &SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}

	err := mgr.StoreSignedPreKey(context.Background(), "uuid", 1, key)
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
}

func TestStoreSignedPreKey_ReplacesExisting(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)

	key1 := &SignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}
	key2 := &SignedPreKey{KeyID: 2, PublicKey: []byte{0x03}, Signature: []byte{0x04}}

	if err := mgr.StoreSignedPreKey(context.Background(), "uuid", 1, key1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mgr.StoreSignedPreKey(context.Background(), "uuid", 1, key2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stored := store.signedKeys[deviceKey("uuid", 1)]
	if stored.KeyID != 2 {
		t.Errorf("expected replaced key with ID 2, got %d", stored.KeyID)
	}
}

// --- StoreKEMPreKeys tests ---

func TestStoreKEMPreKeys_Success(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	preKeys := []*KEMSignedPreKey{
		{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}},
		{KeyID: 2, PublicKey: []byte{0x03}, Signature: []byte{0x04}},
	}

	err := mgr.StoreKEMPreKeys(context.Background(), "uuid", 1, preKeys)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	k := deviceKey("uuid", 1)
	if len(store.kemKeys[k]) != 2 {
		t.Errorf("expected 2 KEM keys, got %d", len(store.kemKeys[k]))
	}
}

func TestStoreKEMPreKeys_EmptySlice(t *testing.T) {
	mgr := NewKeysManager(newMockPreKeyStore())
	err := mgr.StoreKEMPreKeys(context.Background(), "uuid", 1, []*KEMSignedPreKey{})
	if err == nil {
		t.Fatal("expected error for empty slice")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInvalidArgument {
		t.Errorf("expected ErrInvalidArgument, got %d", sigErr.Code)
	}
}

func TestStoreKEMPreKeys_NilSlice(t *testing.T) {
	mgr := NewKeysManager(newMockPreKeyStore())
	err := mgr.StoreKEMPreKeys(context.Background(), "uuid", 1, nil)
	if err == nil {
		t.Fatal("expected error for nil slice")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInvalidArgument {
		t.Errorf("expected ErrInvalidArgument, got %d", sigErr.Code)
	}
}

// --- StoreKEMLastResortPreKey manager tests ---

func TestStoreKEMLastResortPreKey_Success(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	pk := &KEMSignedPreKey{KeyID: 99, PublicKey: []byte{0x99}, Signature: []byte{0x98}}

	err := mgr.StoreKEMLastResortPreKey(context.Background(), "uuid", 1, pk)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	k := deviceKey("uuid", 1)
	if store.kemLastResort[k] == nil {
		t.Fatal("expected last-resort key to be stored")
	}
	if store.kemLastResort[k].KeyID != 99 {
		t.Errorf("expected KeyID 99, got %d", store.kemLastResort[k].KeyID)
	}
}

func TestStoreKEMLastResortPreKey_NilKey(t *testing.T) {
	mgr := NewKeysManager(newMockPreKeyStore())
	err := mgr.StoreKEMLastResortPreKey(context.Background(), "uuid", 1, nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInvalidArgument {
		t.Errorf("expected ErrInvalidArgument, got %d", sigErr.Code)
	}
}

func TestStoreKEMLastResortPreKey_StoreError(t *testing.T) {
	store := newMockPreKeyStore()
	store.storeKEMLastResortErr = errors.New("last-resort store failure")
	mgr := NewKeysManager(store)
	pk := &KEMSignedPreKey{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}

	err := mgr.StoreKEMLastResortPreKey(context.Background(), "uuid", 1, pk)
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
}

func TestStoreKeys_WithKEMLastResortPreKey(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)

	req := &SetKeysRequest{
		KEMLastResortPreKey: &KEMSignedPreKey{KeyID: 77, PublicKey: []byte{0x77}, Signature: []byte{0x78}},
	}
	err := mgr.StoreKeys(context.Background(), "uuid", 1, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	k := deviceKey("uuid", 1)
	if store.kemLastResort[k] == nil {
		t.Fatal("expected last-resort key to be stored via StoreKeys")
	}
	if store.kemLastResort[k].KeyID != 77 {
		t.Errorf("expected KeyID 77, got %d", store.kemLastResort[k].KeyID)
	}
}

func TestStoreKeys_LastResortDoesNotAffectOneTimeKeys(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)

	// Store some one-time KEM keys first.
	req1 := &SetKeysRequest{
		KEMPreKeys: []*KEMSignedPreKey{{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}},
	}
	if err := mgr.StoreKeys(context.Background(), "uuid", 1, req1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Now store a last-resort key; one-time keys must be unaffected.
	req2 := &SetKeysRequest{
		KEMLastResortPreKey: &KEMSignedPreKey{KeyID: 99, PublicKey: []byte{0x99}, Signature: []byte{0x98}},
	}
	if err := mgr.StoreKeys(context.Background(), "uuid", 1, req2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	k := deviceKey("uuid", 1)
	if len(store.kemKeys[k]) != 1 {
		t.Errorf("expected 1 one-time KEM key, got %d", len(store.kemKeys[k]))
	}
	if store.kemLastResort[k] == nil || store.kemLastResort[k].KeyID != 99 {
		t.Errorf("expected last-resort key with KeyID 99")
	}
}

func TestStoreKEMPreKeys_StoreError(t *testing.T) {
	store := newMockPreKeyStore()
	store.storeKEMErr = errors.New("kem store failure")
	mgr := NewKeysManager(store)
	preKeys := []*KEMSignedPreKey{{KeyID: 1, PublicKey: []byte{0x01}, Signature: []byte{0x02}}}

	err := mgr.StoreKEMPreKeys(context.Background(), "uuid", 1, preKeys)
	if err == nil {
		t.Fatal("expected error")
	}
	var sigErr *signalerrors.SignalError
	if !errors.As(err, &sigErr) {
		t.Fatalf("expected SignalError, got %T", err)
	}
	if sigErr.Code != signalerrors.ErrInternal {
		t.Errorf("expected ErrInternal, got %d", sigErr.Code)
	}
}

// --- ListAccountUUIDs ---

func TestListAccountUUIDs_Empty(t *testing.T) {
	mgr := NewKeysManager(newMockPreKeyStore())
	uuids, err := mgr.ListAccountUUIDs(context.Background())
	if err != nil {
		t.Fatalf("ListAccountUUIDs: %v", err)
	}
	if len(uuids) != 0 {
		t.Errorf("expected empty result, got %v", uuids)
	}
}

func TestListAccountUUIDs_NonEmpty(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	ctx := context.Background()

	// Store keys for two different accounts.
	req1 := &SetKeysRequest{
		PreKeys: []*PreKey{{KeyID: 1, PublicKey: []byte("pk1")}},
	}
	if err := mgr.StoreKeys(ctx, "account-aaa", 1, req1); err != nil {
		t.Fatalf("StoreKeys account-aaa: %v", err)
	}
	req2 := &SetKeysRequest{
		PreKeys: []*PreKey{{KeyID: 2, PublicKey: []byte("pk2")}},
	}
	if err := mgr.StoreKeys(ctx, "account-bbb", 1, req2); err != nil {
		t.Fatalf("StoreKeys account-bbb: %v", err)
	}

	uuids, err := mgr.ListAccountUUIDs(ctx)
	if err != nil {
		t.Fatalf("ListAccountUUIDs: %v", err)
	}
	if len(uuids) < 2 {
		t.Errorf("expected at least 2 UUIDs, got %v", uuids)
	}
}

// --- DeleteAllForAccount ---

func TestDeleteAllForAccount_Success(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := NewKeysManager(store)
	ctx := context.Background()

	// Seed some keys for an account.
	req := &SetKeysRequest{
		PreKeys: []*PreKey{{KeyID: 1, PublicKey: []byte("pk")}},
	}
	if err := mgr.StoreKeys(ctx, "del-account", 1, req); err != nil {
		t.Fatalf("StoreKeys: %v", err)
	}

	if err := mgr.DeleteAllForAccount(ctx, "del-account"); err != nil {
		t.Fatalf("DeleteAllForAccount: %v", err)
	}

	// Keys must be gone.
	state, err := mgr.GetPreKeyCount(ctx, "del-account", 1)
	if err != nil {
		t.Fatalf("GetPreKeyCount: %v", err)
	}
	if state.ECCount != 0 {
		t.Errorf("expected 0 EC keys after DeleteAllForAccount, got %d", state.ECCount)
	}
}

func TestDeleteAllForAccount_StoreError(t *testing.T) {
	store := newMockPreKeyStore()
	store.deleteAccErr = errors.New("delete all error")
	mgr := NewKeysManager(store)

	err := mgr.DeleteAllForAccount(context.Background(), "some-uuid")
	if err == nil || err.Error() != "delete all error" {
		t.Errorf("expected delete all error, got: %v", err)
	}
}
