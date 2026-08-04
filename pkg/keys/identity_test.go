package keys

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// inMemoryPreKeyStore is an in-test PreKeyStore used to verify that
// ACI-keyed and PNI-keyed calls land in distinct storage namespaces.
// Importing the main pkg/storage/memory package here would create an
// import cycle because that package depends on pkg/keys.
type inMemoryPreKeyStore struct {
	mu            sync.RWMutex
	ec            map[string][]*PreKey
	kem           map[string][]*KEMSignedPreKey
	kemLastResort map[string]*KEMSignedPreKey
	signed        map[string]*SignedPreKey
}

func newInMemoryPreKeyStore() *inMemoryPreKeyStore {
	return &inMemoryPreKeyStore{
		ec:            make(map[string][]*PreKey),
		kem:           make(map[string][]*KEMSignedPreKey),
		kemLastResort: make(map[string]*KEMSignedPreKey),
		signed:        make(map[string]*SignedPreKey),
	}
}

func keyOf(uuid string, device uint64) string { return fmt.Sprintf("%s/%d", uuid, device) }

func (s *inMemoryPreKeyStore) StoreECPreKeys(_ context.Context, uuid string, device uint64, pks []*PreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ec[keyOf(uuid, device)] = append([]*PreKey(nil), pks...)
	return nil
}

func (s *inMemoryPreKeyStore) StoreKEMPreKeys(_ context.Context, uuid string, device uint64, pks []*KEMSignedPreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kem[keyOf(uuid, device)] = append([]*KEMSignedPreKey(nil), pks...)
	return nil
}

func (s *inMemoryPreKeyStore) StoreKEMLastResortPreKey(_ context.Context, uuid string, device uint64, p *KEMSignedPreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kemLastResort[keyOf(uuid, device)] = p
	return nil
}

func (s *inMemoryPreKeyStore) StoreSignedPreKey(_ context.Context, uuid string, device uint64, p *SignedPreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signed[keyOf(uuid, device)] = p
	return nil
}

func (s *inMemoryPreKeyStore) TakeEC(_ context.Context, uuid string, device uint64) (*PreKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyOf(uuid, device)
	if len(s.ec[k]) == 0 {
		return nil, errors.New("no EC pre-key")
	}
	first := s.ec[k][0]
	s.ec[k] = s.ec[k][1:]
	return first, nil
}

func (s *inMemoryPreKeyStore) TakeKEM(_ context.Context, uuid string, device uint64) (*KEMSignedPreKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyOf(uuid, device)
	if len(s.kem[k]) == 0 {
		return nil, errors.New("no KEM pre-key")
	}
	first := s.kem[k][0]
	s.kem[k] = s.kem[k][1:]
	return first, nil
}

func (s *inMemoryPreKeyStore) GetKEMLastResortPreKey(_ context.Context, uuid string, device uint64) (*KEMSignedPreKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.kemLastResort[keyOf(uuid, device)]
	if !ok {
		return nil, errors.New("no last-resort KEM key")
	}
	return p, nil
}

func (s *inMemoryPreKeyStore) GetSignedPreKey(_ context.Context, uuid string, device uint64) (*SignedPreKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.signed[keyOf(uuid, device)]
	if !ok {
		return nil, errors.New("no signed pre-key")
	}
	return p, nil
}

func (s *inMemoryPreKeyStore) GetPreKeyCount(_ context.Context, uuid string, device uint64) (*PreKeyState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k := keyOf(uuid, device)
	_, hasLR := s.kemLastResort[k]
	return &PreKeyState{
		ECCount:       len(s.ec[k]),
		KEMCount:      len(s.kem[k]),
		HasLastResort: hasLR,
	}, nil
}

func (s *inMemoryPreKeyStore) DeleteAllForDevice(_ context.Context, uuid string, device uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyOf(uuid, device)
	delete(s.ec, k)
	delete(s.kem, k)
	delete(s.kemLastResort, k)
	delete(s.signed, k)
	return nil
}

func (s *inMemoryPreKeyStore) DeleteAllForAccount(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Scan every key and drop those matching the account UUID prefix.
	prefix := uuid + "/"
	for k := range s.ec {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			delete(s.ec, k)
			delete(s.kem, k)
			delete(s.kemLastResort, k)
			delete(s.signed, k)
		}
	}
	return nil
}

func (s *inMemoryPreKeyStore) ListAccountUUIDs(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]struct{})
	for k := range s.ec {
		if i := indexByte(k, '/'); i > 0 {
			seen[k[:i]] = struct{}{}
		}
	}
	for k := range s.kem {
		if i := indexByte(k, '/'); i > 0 {
			seen[k[:i]] = struct{}{}
		}
	}
	for k := range s.signed {
		if i := indexByte(k, '/'); i > 0 {
			seen[k[:i]] = struct{}{}
		}
	}
	for k := range s.kemLastResort {
		if i := indexByte(k, '/'); i > 0 {
			seen[k[:i]] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for u := range seen {
		out = append(out, u)
	}
	return out, nil
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// newManagerWithMemoryStore wires a KeysManager onto an in-test
// in-memory PreKeyStore. The returned manager is suitable for
// exercising the identity-namespaced API without any external
// dependency (and without triggering an import cycle).
func newManagerWithMemoryStore(t *testing.T) *KeysManager {
	t.Helper()
	return NewKeysManager(newInMemoryPreKeyStore())
}

func sampleAccount(aci, pni string) *accounts.Account {
	return &accounts.Account{
		UUID: aci,
		PNI:  pni,
	}
}

func sampleRequest() *SetKeysRequest {
	return &SetKeysRequest{
		PreKeys: []*PreKey{
			{KeyID: 1, PublicKey: []byte("ec-pk-1")},
			{KeyID: 2, PublicKey: []byte("ec-pk-2")},
		},
		SignedPreKey: &SignedPreKey{KeyID: 10, PublicKey: []byte("spk"), Signature: []byte("sig")},
	}
}

// ---- resolveIdentityUUID ----

func TestResolveIdentityUUID_NilAccount(t *testing.T) {
	t.Parallel()
	_, err := resolveIdentityUUID(nil, accounts.IdentityTypeACI)
	if err == nil {
		t.Fatal("expected error for nil account")
	}
}

func TestResolveIdentityUUID_EmptyNamespace(t *testing.T) {
	t.Parallel()
	acct := sampleAccount("aci-value", "") // PNI empty
	if _, err := resolveIdentityUUID(acct, accounts.IdentityTypePNI); !errors.Is(err, ErrIdentityNotSet) {
		t.Fatalf("expected ErrIdentityNotSet for empty PNI, got %v", err)
	}
}

func TestResolveIdentityUUID_ReturnsACIandPNI(t *testing.T) {
	t.Parallel()
	acct := sampleAccount("aci-value", "pni-value")

	aci, err := resolveIdentityUUID(acct, accounts.IdentityTypeACI)
	if err != nil || aci != "aci-value" {
		t.Fatalf("ACI: got (%q, %v), want (\"aci-value\", nil)", aci, err)
	}
	pni, err := resolveIdentityUUID(acct, accounts.IdentityTypePNI)
	if err != nil || pni != "pni-value" {
		t.Fatalf("PNI: got (%q, %v), want (\"pni-value\", nil)", pni, err)
	}
}

// ---- ACI and PNI are truly separate namespaces ----

func TestStoreKeysForIdentity_ACIandPNI_SeparateNamespaces(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := newManagerWithMemoryStore(t)
	acct := sampleAccount("aci-uuid", "pni-uuid")
	const deviceID = 1

	// Store different signed pre-keys under each namespace.
	aciReq := sampleRequest()
	aciReq.SignedPreKey.KeyID = 100
	aciReq.SignedPreKey.PublicKey = []byte("aci-spk")
	if err := m.StoreKeysForIdentity(ctx, acct, accounts.IdentityTypeACI, deviceID, aciReq); err != nil {
		t.Fatalf("StoreKeys ACI: %v", err)
	}

	pniReq := sampleRequest()
	pniReq.SignedPreKey.KeyID = 200
	pniReq.SignedPreKey.PublicKey = []byte("pni-spk")
	if err := m.StoreKeysForIdentity(ctx, acct, accounts.IdentityTypePNI, deviceID, pniReq); err != nil {
		t.Fatalf("StoreKeys PNI: %v", err)
	}

	// Reading back each namespace returns its own SignedPreKey.
	aciItem, err := m.GetPreKeysForIdentity(ctx, acct, accounts.IdentityTypeACI, deviceID)
	if err != nil {
		t.Fatalf("GetPreKeys ACI: %v", err)
	}
	if aciItem.SignedPreKey.KeyID != 100 || string(aciItem.SignedPreKey.PublicKey) != "aci-spk" {
		t.Fatalf("ACI namespace returned wrong signed pre-key: %+v", aciItem.SignedPreKey)
	}

	pniItem, err := m.GetPreKeysForIdentity(ctx, acct, accounts.IdentityTypePNI, deviceID)
	if err != nil {
		t.Fatalf("GetPreKeys PNI: %v", err)
	}
	if pniItem.SignedPreKey.KeyID != 200 || string(pniItem.SignedPreKey.PublicKey) != "pni-spk" {
		t.Fatalf("PNI namespace returned wrong signed pre-key: %+v", pniItem.SignedPreKey)
	}
}

func TestPreKeyCountForIdentity_Independent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := newManagerWithMemoryStore(t)
	acct := sampleAccount("aci", "pni")
	const deviceID = 1

	// ACI gets 3 pre-keys; PNI gets 1.
	aciReq := &SetKeysRequest{
		PreKeys: []*PreKey{
			{KeyID: 1, PublicKey: []byte("a1")},
			{KeyID: 2, PublicKey: []byte("a2")},
			{KeyID: 3, PublicKey: []byte("a3")},
		},
		SignedPreKey: &SignedPreKey{KeyID: 99, PublicKey: []byte("spk"), Signature: []byte("sig")},
	}
	pniReq := &SetKeysRequest{
		PreKeys:      []*PreKey{{KeyID: 1, PublicKey: []byte("p1")}},
		SignedPreKey: &SignedPreKey{KeyID: 99, PublicKey: []byte("spk"), Signature: []byte("sig")},
	}

	if err := m.StoreKeysForIdentity(ctx, acct, accounts.IdentityTypeACI, deviceID, aciReq); err != nil {
		t.Fatal(err)
	}
	if err := m.StoreKeysForIdentity(ctx, acct, accounts.IdentityTypePNI, deviceID, pniReq); err != nil {
		t.Fatal(err)
	}

	aciState, _ := m.GetPreKeyCountForIdentity(ctx, acct, accounts.IdentityTypeACI, deviceID)
	if aciState.ECCount != 3 {
		t.Fatalf("ACI count: want 3, got %d", aciState.ECCount)
	}
	pniState, _ := m.GetPreKeyCountForIdentity(ctx, acct, accounts.IdentityTypePNI, deviceID)
	if pniState.ECCount != 1 {
		t.Fatalf("PNI count: want 1, got %d", pniState.ECCount)
	}
}

// ---- Errors propagate correctly through the identity wrappers ----

func TestStoreKeysForIdentity_NilAccount_Rejected(t *testing.T) {
	t.Parallel()
	m := newManagerWithMemoryStore(t)
	err := m.StoreKeysForIdentity(context.Background(), nil, accounts.IdentityTypeACI, 1, sampleRequest())
	if err == nil {
		t.Fatal("expected error for nil account")
	}
	// Error must be a SignalError with ErrInvalidArgument code.
	var se *signalerrors.SignalError
	if !errors.As(err, &se) || se.Code != signalerrors.ErrInvalidArgument {
		t.Fatalf("expected *SignalError with ErrInvalidArgument code, got %v (%T)", err, err)
	}
}

func TestStoreKeysForIdentity_MissingPNI_ReturnsErrIdentityNotSet(t *testing.T) {
	t.Parallel()
	m := newManagerWithMemoryStore(t)
	acct := sampleAccount("aci", "") // no PNI
	err := m.StoreKeysForIdentity(context.Background(), acct, accounts.IdentityTypePNI, 1, sampleRequest())
	if !errors.Is(err, ErrIdentityNotSet) {
		t.Fatalf("expected ErrIdentityNotSet, got %v", err)
	}
}

func TestStoreSignedPreKeyForIdentity_ReachesStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := newManagerWithMemoryStore(t)
	acct := sampleAccount("aci", "pni")
	const deviceID = 7

	spk := &SignedPreKey{KeyID: 1, PublicKey: []byte("pk"), Signature: []byte("sig")}
	if err := m.StoreSignedPreKeyForIdentity(ctx, acct, accounts.IdentityTypePNI, deviceID, spk); err != nil {
		t.Fatal(err)
	}

	// The key is readable via the PNI identifier.
	item, _ := m.GetPreKeysForIdentity(ctx, acct, accounts.IdentityTypePNI, deviceID)
	if item == nil || item.SignedPreKey == nil || item.SignedPreKey.KeyID != 1 {
		t.Fatalf("PNI signed pre-key not retrievable: %+v", item)
	}
}

func TestStoreKEMPreKeysForIdentity_AndLastResort(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := newManagerWithMemoryStore(t)
	acct := sampleAccount("aci", "pni")
	const deviceID = 1

	oneTime := []*KEMSignedPreKey{
		{KeyID: 1, PublicKey: []byte("pk1"), Signature: []byte("sig1")},
	}
	if err := m.StoreKEMPreKeysForIdentity(ctx, acct, accounts.IdentityTypeACI, deviceID, oneTime); err != nil {
		t.Fatal(err)
	}
	lastResort := &KEMSignedPreKey{KeyID: 42, PublicKey: []byte("lr"), Signature: []byte("sig"), IsLastResort: true}
	if err := m.StoreKEMLastResortPreKeyForIdentity(ctx, acct, accounts.IdentityTypeACI, deviceID, lastResort); err != nil {
		t.Fatal(err)
	}

	state, _ := m.GetPreKeyCountForIdentity(ctx, acct, accounts.IdentityTypeACI, deviceID)
	if state.KEMCount != 1 {
		t.Fatalf("expected 1 KEM one-time key, got %d", state.KEMCount)
	}
	if !state.HasLastResort {
		t.Fatal("expected last-resort key to be present")
	}
}
