package service

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// testCtx returns a background context suitable for use in tests.
func testCtx() context.Context {
	return context.Background()
}

// ─── Accounts store mock ─────────────────────────────────────────────────────

type mockAccountStore struct {
	mu       sync.RWMutex
	data     map[string]*accounts.Account
	byNumber map[string]string // number → uuid

	createErr error
	updateErr error
	getErr    error
	deleteErr error
}

func newMockAccountStore() *mockAccountStore {
	return &mockAccountStore{
		data:     make(map[string]*accounts.Account),
		byNumber: make(map[string]string),
	}
}

func (s *mockAccountStore) Create(_ context.Context, a *accounts.Account) error {
	if s.createErr != nil {
		return s.createErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *a
	s.data[a.UUID] = &cp
	s.byNumber[a.Number] = a.UUID
	return nil
}

func (s *mockAccountStore) Get(_ context.Context, uuid string) (*accounts.Account, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.data[uuid]
	if !ok {
		return nil, &accounts.AccountNotFoundError{Identifier: uuid}
	}
	cp := *a
	return &cp, nil
}

func (s *mockAccountStore) GetByNumber(_ context.Context, number string) (*accounts.Account, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	uuid, ok := s.byNumber[number]
	if !ok {
		return nil, &accounts.AccountNotFoundError{Identifier: number}
	}
	a := s.data[uuid]
	cp := *a
	return &cp, nil
}

func (s *mockAccountStore) Update(_ context.Context, a *accounts.Account) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[a.UUID]; !ok {
		return &accounts.AccountNotFoundError{Identifier: a.UUID}
	}
	cp := *a
	s.data[a.UUID] = &cp
	return nil
}

func (s *mockAccountStore) Delete(_ context.Context, uuid string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.data[uuid]
	if !ok {
		return &accounts.AccountNotFoundError{Identifier: uuid}
	}
	delete(s.byNumber, a.Number)
	delete(s.data, uuid)
	return nil
}

// newTestAccount builds a minimal valid Account for use in tests.
func newTestAccount(uuid, number string) *accounts.Account {
	return &accounts.Account{
		UUID:        uuid,
		Number:      number,
		IdentityKey: []byte("testidentitykey32bytespadding!!"),
		Devices: []accounts.Device{
			{
				ID:        accounts.PrimaryDeviceID,
				AuthToken: "test-auth-token",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte("testpublickey"),
					Signature: []byte("testsignature"),
				},
			},
		},
	}
}

// ─── Keys store mock ─────────────────────────────────────────────────────────

type mockPreKeyStore struct {
	mu          sync.Mutex
	ecKeys      map[string][]*keys.PreKey
	kemKeys     map[string][]*keys.KEMSignedPreKey
	signedKeys  map[string]*keys.SignedPreKey
	storeECErr  error
	storeKEMErr error
	signedErr   error
	countErr    error
}

func newMockPreKeyStore() *mockPreKeyStore {
	return &mockPreKeyStore{
		ecKeys:     make(map[string][]*keys.PreKey),
		kemKeys:    make(map[string][]*keys.KEMSignedPreKey),
		signedKeys: make(map[string]*keys.SignedPreKey),
	}
}

func preKeyDeviceKey(uuid string, deviceID uint64) string {
	return fmt.Sprintf("%s:%d", uuid, deviceID)
}

func (s *mockPreKeyStore) StoreECPreKeys(_ context.Context, uuid string, deviceID uint64, pks []*keys.PreKey) error {
	if s.storeECErr != nil {
		return s.storeECErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := preKeyDeviceKey(uuid, deviceID)
	s.ecKeys[k] = append(s.ecKeys[k], pks...)
	return nil
}

func (s *mockPreKeyStore) StoreKEMPreKeys(_ context.Context, uuid string, deviceID uint64, pks []*keys.KEMSignedPreKey) error {
	if s.storeKEMErr != nil {
		return s.storeKEMErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := preKeyDeviceKey(uuid, deviceID)
	s.kemKeys[k] = append(s.kemKeys[k], pks...)
	return nil
}

func (s *mockPreKeyStore) StoreKEMLastResortPreKey(_ context.Context, uuid string, deviceID uint64, pk *keys.KEMSignedPreKey) error {
	return nil
}

func (s *mockPreKeyStore) StoreSignedPreKey(_ context.Context, uuid string, deviceID uint64, spk *keys.SignedPreKey) error {
	if s.signedErr != nil {
		return s.signedErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signedKeys[preKeyDeviceKey(uuid, deviceID)] = spk
	return nil
}

func (s *mockPreKeyStore) TakeEC(_ context.Context, uuid string, deviceID uint64) (*keys.PreKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := preKeyDeviceKey(uuid, deviceID)
	list := s.ecKeys[k]
	if len(list) == 0 {
		return nil, errors.New("no EC pre-keys")
	}
	pk := list[0]
	s.ecKeys[k] = list[1:]
	return pk, nil
}

func (s *mockPreKeyStore) TakeKEM(_ context.Context, uuid string, deviceID uint64) (*keys.KEMSignedPreKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := preKeyDeviceKey(uuid, deviceID)
	list := s.kemKeys[k]
	if len(list) == 0 {
		return nil, errors.New("no KEM pre-keys")
	}
	pk := list[0]
	s.kemKeys[k] = list[1:]
	return pk, nil
}

func (s *mockPreKeyStore) GetKEMLastResortPreKey(_ context.Context, uuid string, deviceID uint64) (*keys.KEMSignedPreKey, error) {
	return nil, errors.New("no last-resort KEM pre-key")
}

func (s *mockPreKeyStore) GetSignedPreKey(_ context.Context, uuid string, deviceID uint64) (*keys.SignedPreKey, error) {
	if s.signedErr != nil {
		return nil, s.signedErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := preKeyDeviceKey(uuid, deviceID)
	spk, ok := s.signedKeys[k]
	if !ok {
		return nil, errors.New("signed pre-key not found")
	}
	return spk, nil
}

func (s *mockPreKeyStore) GetPreKeyCount(_ context.Context, uuid string, deviceID uint64) (*keys.PreKeyState, error) {
	if s.countErr != nil {
		return nil, s.countErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := preKeyDeviceKey(uuid, deviceID)
	return &keys.PreKeyState{
		ECCount:  len(s.ecKeys[k]),
		KEMCount: len(s.kemKeys[k]),
	}, nil
}

func (s *mockPreKeyStore) DeleteAllForDevice(_ context.Context, uuid string, deviceID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := preKeyDeviceKey(uuid, deviceID)
	delete(s.ecKeys, k)
	delete(s.kemKeys, k)
	delete(s.signedKeys, k)
	return nil
}

func (s *mockPreKeyStore) DeleteAllForAccount(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.ecKeys {
		if len(k) >= len(uuid) && k[:len(uuid)] == uuid {
			delete(s.ecKeys, k)
		}
	}
	for k := range s.kemKeys {
		if len(k) >= len(uuid) && k[:len(uuid)] == uuid {
			delete(s.kemKeys, k)
		}
	}
	for k := range s.signedKeys {
		if len(k) >= len(uuid) && k[:len(uuid)] == uuid {
			delete(s.signedKeys, k)
		}
	}
	return nil
}

// ─── Messages store mock ─────────────────────────────────────────────────────

type mockMessageStore struct {
	mu        sync.Mutex
	envelopes map[string][]*messages.Envelope // key: "uuid:deviceID"
	insertErr error
	getErr    error
	deleteErr error
}

func newMockMessageStore() *mockMessageStore {
	return &mockMessageStore{
		envelopes: make(map[string][]*messages.Envelope),
	}
}

func msgDeviceKey(uuid string, deviceID uint64) string {
	return fmt.Sprintf("%s:%d", uuid, deviceID)
}

func (s *mockMessageStore) Insert(_ context.Context, uuid string, deviceID uint64, env *messages.Envelope) (uint64, error) {
	if s.insertErr != nil {
		return 0, s.insertErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := msgDeviceKey(uuid, deviceID)
	cp := *env
	cp.ID = uint64(len(s.envelopes[k]) + 1)
	s.envelopes[k] = append(s.envelopes[k], &cp)
	return cp.ID, nil
}

func (s *mockMessageStore) GetMessagesForDevice(_ context.Context, uuid string, deviceID uint64) ([]*messages.Envelope, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k := msgDeviceKey(uuid, deviceID)
	list := s.envelopes[k]
	out := make([]*messages.Envelope, len(list))
	copy(out, list)
	return out, nil
}

func (s *mockMessageStore) Delete(_ context.Context, uuid string, serverGUID string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, list := range s.envelopes {
		filtered := list[:0]
		for _, e := range list {
			if e.ServerGUID != serverGUID {
				filtered = append(filtered, e)
			}
		}
		s.envelopes[k] = filtered
	}
	return nil
}

func (s *mockMessageStore) DeleteForDevice(_ context.Context, uuid string, deviceID uint64) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.envelopes, msgDeviceKey(uuid, deviceID))
	return nil
}

func (s *mockMessageStore) DeleteForAccount(_ context.Context, uuid string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.envelopes {
		if len(k) >= len(uuid) && k[:len(uuid)] == uuid {
			delete(s.envelopes, k)
		}
	}
	return nil
}

// ─── Profiles store mock ─────────────────────────────────────────────────────

type mockProfileStore struct {
	mu     sync.RWMutex
	data   map[string]*profiles.Profile // key: "uuid:version"
	setErr error
	getErr error
}

func newMockProfileStore() *mockProfileStore {
	return &mockProfileStore{data: make(map[string]*profiles.Profile)}
}

func profileKey(uuid, version string) string {
	return uuid + ":" + version
}

func (s *mockProfileStore) Set(_ context.Context, p *profiles.Profile) error {
	if s.setErr != nil {
		return s.setErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *p
	s.data[profileKey(p.UUID, p.Version)] = &cp
	return nil
}

func (s *mockProfileStore) Get(_ context.Context, uuid, version string) (*profiles.Profile, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.data[profileKey(uuid, version)]
	if !ok {
		return nil, errors.New("profile not found")
	}
	cp := *p
	return &cp, nil
}

func (s *mockProfileStore) GetLatest(_ context.Context, uuid string) (*profiles.Profile, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var latest *profiles.Profile
	for k, p := range s.data {
		if len(k) >= len(uuid) && k[:len(uuid)] == uuid {
			if latest == nil || p.Version > latest.Version {
				cp := *p
				latest = &cp
			}
		}
	}
	if latest == nil {
		return nil, errors.New("profile not found")
	}
	return latest, nil
}

func (s *mockProfileStore) Delete(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.data {
		if len(k) >= len(uuid) && k[:len(uuid)] == uuid {
			delete(s.data, k)
		}
	}
	return nil
}

// ─── Usernames store mock ────────────────────────────────────────────────────

type mockUsernameStore struct {
	mu           sync.Mutex
	hashes       map[string][]byte                  // uuid → confirmed hash
	reservations map[string]string                  // uuid → token
	links        map[string]*usernames.UsernameLink // handle → link
	reserveErr   error
	confirmErr   error
	lookupErr    error
	deleteErr    error
	linkErr      error
	getLinkErr   error
}

func newMockUsernameStore() *mockUsernameStore {
	return &mockUsernameStore{
		hashes:       make(map[string][]byte),
		reservations: make(map[string]string),
		links:        make(map[string]*usernames.UsernameLink),
	}
}

func (s *mockUsernameStore) ReserveHash(_ context.Context, uuid string, hashes [][]byte) ([]byte, string, error) {
	if s.reserveErr != nil {
		return nil, "", s.reserveErr
	}
	token := "token-" + uuid
	s.mu.Lock()
	s.reservations[uuid] = token
	s.mu.Unlock()
	return hashes[0], token, nil
}

func (s *mockUsernameStore) ConfirmHash(_ context.Context, uuid string, hash []byte, token string) error {
	if s.confirmErr != nil {
		return s.confirmErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hashes[uuid] = hash
	return nil
}

func (s *mockUsernameStore) LookupByHash(_ context.Context, hash []byte) (string, error) {
	if s.lookupErr != nil {
		return "", s.lookupErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for uuid, h := range s.hashes {
		if string(h) == string(hash) {
			return uuid, nil
		}
	}
	return "", errors.New("not found")
}

func (s *mockUsernameStore) DeleteHash(_ context.Context, uuid string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.hashes, uuid)
	return nil
}

func (s *mockUsernameStore) SetLink(_ context.Context, link *usernames.UsernameLink) error {
	if s.linkErr != nil {
		return s.linkErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *link
	s.links[link.UsernameLinkHandle] = &cp
	return nil
}

func (s *mockUsernameStore) GetLink(_ context.Context, handle string) (*usernames.UsernameLink, error) {
	if s.getLinkErr != nil {
		return nil, s.getLinkErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	link, ok := s.links[handle]
	if !ok {
		return nil, errors.New("link not found")
	}
	cp := *link
	return &cp, nil
}

func (s *mockUsernameStore) DeleteLink(_ context.Context, uuid string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for handle, link := range s.links {
		if link.UUID == uuid {
			delete(s.links, handle)
		}
	}
	return nil
}

// ─── Calling stubs ───────────────────────────────────────────────────────────

// noOpTurnProvider satisfies calling.TurnCredentialProvider by returning an
// empty token with no error. Used in service-level tests that need a
// CallingManager but do not exercise TURN credential retrieval.
type noOpTurnProvider struct{}

func (noOpTurnProvider) RetrieveCredentials(_ context.Context) (*calling.TurnToken, error) {
	return &calling.TurnToken{}, nil
}

// noOpSurveyPublisher satisfies calling.SurveyPublisher by discarding all
// published surveys without error.
type noOpSurveyPublisher struct{}

func (noOpSurveyPublisher) Publish(_ context.Context, _ *calling.CallQualitySurveyMessage) error {
	return nil
}

// Compile-time interface checks.
var _ calling.TurnCredentialProvider = noOpTurnProvider{}
var _ calling.SurveyPublisher = noOpSurveyPublisher{}
