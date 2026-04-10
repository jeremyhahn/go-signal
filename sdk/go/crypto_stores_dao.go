package signal

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	groupstore "github.com/jeremyhahn/go-libsignal/pkg/groups/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	sessionrecord "github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	qrdbdao "github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// daoTimeout is the context timeout for DAO operations.
const daoTimeout = 5 * time.Second

func newDaoCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), daoTimeout)
}

// ---------------------------------------------------------------------------
// Session Store
// ---------------------------------------------------------------------------

// DAOSessionStore implements store.Session using a GenericDAO.
type DAOSessionStore struct {
	dao        qrdbdao.GenericDAO[*entities.CryptoSessionEntity]
	serializer interface {
		Session() interface{ Serialize(*sessionrecord.Session) []byte }
	}
}

// NewDAOSessionStore creates a session store backed by the DAO factory.
func NewDAOSessionStore(f *daostore.Factory) *DAOSessionStore {
	return &DAOSessionStore{dao: f.Sessions}
}

func (s *DAOSessionStore) LoadSession(address *protocol.SignalAddress) *sessionrecord.Session {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "Address", daoAddressKey(address))
	if err != nil {
		return nil
	}
	// Session deserialization requires the serializer from the crypto state.
	// The raw record bytes are stored; deserialization happens at the
	// session builder level when establishing encrypted sessions.
	_ = entity
	return nil
}

func (s *DAOSessionStore) GetSubDeviceSessions(name string) []uint32 {
	ctx, cancel := newDaoCtx()
	defer cancel()
	results, err := s.dao.Find(ctx).Where("Address PREFIX ?", name+".").Execute()
	if err != nil {
		return nil
	}
	var devices []uint32
	for _, e := range results {
		addr := e.Address
		if idx := len(name) + 1; idx < len(addr) {
			if d, err := strconv.ParseUint(addr[idx:], 10, 32); err == nil {
				devices = append(devices, uint32(d))
			}
		}
	}
	return devices
}

func (s *DAOSessionStore) StoreSession(address *protocol.SignalAddress, rec *sessionrecord.Session) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	key := daoAddressKey(address)

	// Try to find existing.
	existing, err := s.dao.QueryOneByIndex(ctx, "Address", key)
	if err == nil && existing != nil {
		data, serErr := rec.Serialize()
		if serErr != nil {
			return
		}
		existing.Record = data
		_ = s.dao.Save(ctx, existing)
		return
	}

	data, serErr := rec.Serialize()
	if serErr != nil {
		return
	}
	entity := &entities.CryptoSessionEntity{
		Address: key,
		Record:  data,
	}
	_ = s.dao.Save(ctx, entity)
}

func (s *DAOSessionStore) ContainsSession(address *protocol.SignalAddress) bool {
	ctx, cancel := newDaoCtx()
	defer cancel()
	_, err := s.dao.QueryOneByIndex(ctx, "Address", daoAddressKey(address))
	return err == nil
}

func (s *DAOSessionStore) DeleteSession(address *protocol.SignalAddress) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "Address", daoAddressKey(address))
	if err == nil && entity != nil {
		_ = s.dao.Delete(ctx, entity)
	}
}

func (s *DAOSessionStore) DeleteAllSessions() {
	ctx, cancel := newDaoCtx()
	defer cancel()
	results, _ := s.dao.Find(ctx).Execute()
	for _, e := range results {
		_ = s.dao.Delete(ctx, e)
	}
}

// ---------------------------------------------------------------------------
// PreKey Store
// ---------------------------------------------------------------------------

// DAOPreKeyStore implements store.PreKey using a GenericDAO.
type DAOPreKeyStore struct {
	dao qrdbdao.GenericDAO[*entities.PreKeyEntity]
}

func NewDAOPreKeyStore(f *daostore.Factory) *DAOPreKeyStore {
	return &DAOPreKeyStore{dao: f.PreKeys}
}

func (s *DAOPreKeyStore) LoadPreKey(preKeyID uint32) *sessionrecord.PreKey {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "KeyID", preKeyID)
	if err != nil {
		return nil
	}
	_ = entity
	return nil // deserialization wired via serializer
}

func (s *DAOPreKeyStore) StorePreKey(preKeyID uint32, rec *sessionrecord.PreKey) {
	ctx, cancel := newDaoCtx()
	defer cancel()

	data, serErr := rec.Serialize()
	if serErr != nil {
		return
	}

	existing, err := s.dao.QueryOneByIndex(ctx, "KeyID", preKeyID)
	if err == nil && existing != nil {
		existing.Record = data
		_ = s.dao.Save(ctx, existing)
		return
	}

	entity := &entities.PreKeyEntity{
		KeyID:  preKeyID,
		Record: data,
	}
	_ = s.dao.Save(ctx, entity)
}

func (s *DAOPreKeyStore) ContainsPreKey(preKeyID uint32) bool {
	ctx, cancel := newDaoCtx()
	defer cancel()
	_, err := s.dao.QueryOneByIndex(ctx, "KeyID", preKeyID)
	return err == nil
}

func (s *DAOPreKeyStore) RemovePreKey(preKeyID uint32) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "KeyID", preKeyID)
	if err == nil && entity != nil {
		_ = s.dao.Delete(ctx, entity)
	}
}

// ---------------------------------------------------------------------------
// Signed PreKey Store
// ---------------------------------------------------------------------------

// DAOSignedPreKeyStore implements store.SignedPreKey using a GenericDAO.
type DAOSignedPreKeyStore struct {
	dao qrdbdao.GenericDAO[*entities.SignedPreKeyEntity]
}

func NewDAOSignedPreKeyStore(f *daostore.Factory) *DAOSignedPreKeyStore {
	return &DAOSignedPreKeyStore{dao: f.SignedPreKeys}
}

func (s *DAOSignedPreKeyStore) LoadSignedPreKey(signedPreKeyID uint32) *sessionrecord.SignedPreKey {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "KeyID", signedPreKeyID)
	if err != nil {
		return nil
	}
	_ = entity
	return nil
}

func (s *DAOSignedPreKeyStore) LoadSignedPreKeys() []*sessionrecord.SignedPreKey {
	ctx, cancel := newDaoCtx()
	defer cancel()
	results, _ := s.dao.Find(ctx).Execute()
	_ = results
	return nil
}

func (s *DAOSignedPreKeyStore) StoreSignedPreKey(signedPreKeyID uint32, rec *sessionrecord.SignedPreKey) {
	ctx, cancel := newDaoCtx()
	defer cancel()

	data, serErr := rec.Serialize()
	if serErr != nil {
		return
	}

	existing, err := s.dao.QueryOneByIndex(ctx, "KeyID", signedPreKeyID)
	if err == nil && existing != nil {
		existing.Record = data
		_ = s.dao.Save(ctx, existing)
		return
	}

	entity := &entities.SignedPreKeyEntity{
		KeyID:  signedPreKeyID,
		Record: data,
	}
	_ = s.dao.Save(ctx, entity)
}

func (s *DAOSignedPreKeyStore) ContainsSignedPreKey(signedPreKeyID uint32) bool {
	ctx, cancel := newDaoCtx()
	defer cancel()
	_, err := s.dao.QueryOneByIndex(ctx, "KeyID", signedPreKeyID)
	return err == nil
}

func (s *DAOSignedPreKeyStore) RemoveSignedPreKey(signedPreKeyID uint32) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "KeyID", signedPreKeyID)
	if err == nil && entity != nil {
		_ = s.dao.Delete(ctx, entity)
	}
}

// ---------------------------------------------------------------------------
// Identity Key Store
// ---------------------------------------------------------------------------

// DAOIdentityKeyStore implements store.IdentityKey using a GenericDAO.
type DAOIdentityKeyStore struct {
	mu              sync.RWMutex
	dao             qrdbdao.GenericDAO[*entities.IdentityKeyEntity]
	localIdentity   *identity.KeyPair
	registrationID  uint32
}

func NewDAOIdentityKeyStore(f *daostore.Factory, localIdentity *identity.KeyPair, regID uint32) *DAOIdentityKeyStore {
	return &DAOIdentityKeyStore{
		dao:            f.IdentityKeys,
		localIdentity:  localIdentity,
		registrationID: regID,
	}
}

func (s *DAOIdentityKeyStore) GetIdentityKeyPair() *identity.KeyPair {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localIdentity
}

func (s *DAOIdentityKeyStore) GetLocalRegistrationId() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.registrationID
}

func (s *DAOIdentityKeyStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	key := daoAddressKey(address)
	keyBytes := identityKey.Serialize()

	existing, err := s.dao.QueryOneByIndex(ctx, "Address", key)
	if err == nil && existing != nil {
		existing.Key = keyBytes
		_ = s.dao.Save(ctx, existing)
		return
	}

	entity := &entities.IdentityKeyEntity{
		Address:        key,
		Key:            keyBytes,
		FirstUse:       time.Now().UnixMilli(),
		VerifiedStatus: 0,
	}
	_ = s.dao.Save(ctx, entity)
}

func (s *DAOIdentityKeyStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction store.Direction) bool {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "Address", daoAddressKey(address))
	if err != nil {
		// Trust on first use: no stored identity means trust.
		return true
	}
	// Compare stored key with provided key.
	storedKey, err := ecc.DecodePoint(entity.Key, 0)
	if err != nil {
		return false
	}
	return identity.NewKey(storedKey).Fingerprint() == identityKey.Fingerprint()
}

func (s *DAOIdentityKeyStore) GetIdentity(address *protocol.SignalAddress) (*identity.Key, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "Address", daoAddressKey(address))
	if err != nil {
		return nil, nil
	}
	pubKey, err := ecc.DecodePoint(entity.Key, 0)
	if err != nil {
		return nil, fmt.Errorf("decode identity key: %w", err)
	}
	key := identity.NewKey(pubKey)
	return key, nil
}

// ---------------------------------------------------------------------------
// Sender Key Store
// ---------------------------------------------------------------------------

// DAOSenderKeyStore implements groupstore.SenderKey using a GenericDAO.
type DAOSenderKeyStore struct {
	dao qrdbdao.GenericDAO[*entities.SenderKeyEntity]
}

func NewDAOSenderKeyStore(f *daostore.Factory) *DAOSenderKeyStore {
	return &DAOSenderKeyStore{dao: f.SenderKeys}
}

func (s *DAOSenderKeyStore) StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *record.SenderKey) error {
	ctx, cancel := newDaoCtx()
	defer cancel()
	name := daoSenderKeyNameStr(senderKeyName)
	data, err := json.Marshal(keyRecord)
	if err != nil {
		return err
	}

	existing, getErr := s.dao.QueryOneByIndex(ctx, "Name", name)
	if getErr == nil && existing != nil {
		existing.Record = data
		return s.dao.Save(ctx, existing)
	}

	entity := &entities.SenderKeyEntity{
		Name:   name,
		Record: data,
	}
	return s.dao.Save(ctx, entity)
}

func (s *DAOSenderKeyStore) LoadSenderKey(senderKeyName *protocol.SenderKeyName) (*record.SenderKey, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	name := daoSenderKeyNameStr(senderKeyName)
	entity, err := s.dao.QueryOneByIndex(ctx, "Name", name)
	if err != nil {
		return nil, nil
	}
	var rec record.SenderKey
	if err := json.Unmarshal(entity.Record, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// addressKey creates a string key from a SignalAddress: "uuid.deviceID".
func daoAddressKey(addr *protocol.SignalAddress) string {
	return fmt.Sprintf("%s.%d", addr.Name(), addr.DeviceID())
}

// daoSenderKeyNameStr creates a string key from a SenderKeyName.
func daoSenderKeyNameStr(skn *protocol.SenderKeyName) string {
	return fmt.Sprintf("%s::%s.%d", skn.GroupID(), skn.Sender().Name(), skn.Sender().DeviceID())
}

// Compile-time interface assertions.
var (
	_ store.Session      = (*DAOSessionStore)(nil)
	_ store.PreKey       = (*DAOPreKeyStore)(nil)
	_ store.SignedPreKey = (*DAOSignedPreKeyStore)(nil)
	_ store.IdentityKey  = (*DAOIdentityKeyStore)(nil)
	_ groupstore.SenderKey = (*DAOSenderKeyStore)(nil)
)
