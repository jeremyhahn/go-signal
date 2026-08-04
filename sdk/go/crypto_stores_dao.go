package signal

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	groupstore "github.com/jeremyhahn/go-libsignal/pkg/groups/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
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
	serializer *serialize.Serializer
}

// NewDAOSessionStore creates a session store backed by the DAO factory.
func NewDAOSessionStore(f *daostore.Factory) *DAOSessionStore {
	return &DAOSessionStore{
		dao:        f.Sessions,
		serializer: serialize.NewProtobufSerializer(),
	}
}

func (s *DAOSessionStore) LoadSession(address *protocol.SignalAddress) (*sessionrecord.Session, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "Address", daoAddressKey(address))
	if err != nil {
		// Treat lookup misses as "not found" rather than I/O failure.
		return nil, nil
	}
	if entity == nil || len(entity.Record) == 0 {
		return nil, nil
	}
	rec, err := sessionrecord.NewSessionFromBytes(entity.Record, s.serializer.Session, s.serializer.State)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "deserialize session", err)
	}
	return rec, nil
}

func (s *DAOSessionStore) GetSubDeviceSessions(name string) ([]uint32, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	results, err := s.dao.Find(ctx).Where("Address PREFIX ?", name+".").Execute()
	if err != nil {
		return nil, err
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
	return devices, nil
}

func (s *DAOSessionStore) StoreSession(address *protocol.SignalAddress, rec *sessionrecord.Session) error {
	ctx, cancel := newDaoCtx()
	defer cancel()
	key := daoAddressKey(address)

	data, err := rec.Serialize()
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "serialize session", err)
	}

	existing, lookupErr := s.dao.QueryOneByIndex(ctx, "Address", key)
	if lookupErr == nil && existing != nil {
		existing.Record = data
		return s.dao.Save(ctx, existing)
	}

	entity := &entities.CryptoSessionEntity{
		Address: key,
		Record:  data,
	}
	return s.dao.Save(ctx, entity)
}

func (s *DAOSessionStore) ContainsSession(address *protocol.SignalAddress) (bool, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	_, err := s.dao.QueryOneByIndex(ctx, "Address", daoAddressKey(address))
	if err != nil {
		// QueryOneByIndex returns an error for "not found"; surface that as
		// (false, nil) per the interface contract.
		return false, nil
	}
	return true, nil
}

func (s *DAOSessionStore) DeleteSession(address *protocol.SignalAddress) error {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "Address", daoAddressKey(address))
	if err != nil || entity == nil {
		return nil
	}
	return s.dao.Delete(ctx, entity)
}

func (s *DAOSessionStore) DeleteAllSessions() error {
	ctx, cancel := newDaoCtx()
	defer cancel()
	results, err := s.dao.Find(ctx).Execute()
	if err != nil {
		return err
	}
	for _, e := range results {
		if err := s.dao.Delete(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// PreKey Store
// ---------------------------------------------------------------------------

// DAOPreKeyStore implements store.PreKey using a GenericDAO.
type DAOPreKeyStore struct {
	dao        qrdbdao.GenericDAO[*entities.PreKeyEntity]
	serializer *serialize.Serializer
}

func NewDAOPreKeyStore(f *daostore.Factory) *DAOPreKeyStore {
	return &DAOPreKeyStore{
		dao:        f.PreKeys,
		serializer: serialize.NewProtobufSerializer(),
	}
}

func (s *DAOPreKeyStore) LoadPreKey(preKeyID uint32) (*sessionrecord.PreKey, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "KeyID", preKeyID)
	if err != nil {
		return nil, nil
	}
	if entity == nil || len(entity.Record) == 0 {
		return nil, nil
	}
	rec, err := sessionrecord.NewPreKeyFromBytes(entity.Record, s.serializer.PreKeyRecord)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "deserialize pre-key", err)
	}
	return rec, nil
}

func (s *DAOPreKeyStore) StorePreKey(preKeyID uint32, rec *sessionrecord.PreKey) error {
	ctx, cancel := newDaoCtx()
	defer cancel()

	data, err := rec.Serialize()
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "serialize pre-key", err)
	}

	existing, lookupErr := s.dao.QueryOneByIndex(ctx, "KeyID", preKeyID)
	if lookupErr == nil && existing != nil {
		existing.Record = data
		return s.dao.Save(ctx, existing)
	}

	entity := &entities.PreKeyEntity{
		KeyID:  preKeyID,
		Record: data,
	}
	return s.dao.Save(ctx, entity)
}

func (s *DAOPreKeyStore) ContainsPreKey(preKeyID uint32) (bool, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	_, err := s.dao.QueryOneByIndex(ctx, "KeyID", preKeyID)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (s *DAOPreKeyStore) RemovePreKey(preKeyID uint32) error {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "KeyID", preKeyID)
	if err != nil || entity == nil {
		return nil
	}
	return s.dao.Delete(ctx, entity)
}

// ---------------------------------------------------------------------------
// Signed PreKey Store
// ---------------------------------------------------------------------------

// DAOSignedPreKeyStore implements store.SignedPreKey using a GenericDAO.
type DAOSignedPreKeyStore struct {
	dao        qrdbdao.GenericDAO[*entities.SignedPreKeyEntity]
	serializer *serialize.Serializer
}

func NewDAOSignedPreKeyStore(f *daostore.Factory) *DAOSignedPreKeyStore {
	return &DAOSignedPreKeyStore{
		dao:        f.SignedPreKeys,
		serializer: serialize.NewProtobufSerializer(),
	}
}

func (s *DAOSignedPreKeyStore) LoadSignedPreKey(signedPreKeyID uint32) (*sessionrecord.SignedPreKey, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "KeyID", signedPreKeyID)
	if err != nil {
		return nil, nil
	}
	if entity == nil || len(entity.Record) == 0 {
		return nil, nil
	}
	rec, err := sessionrecord.NewSignedPreKeyFromBytes(entity.Record, s.serializer.SignedPreKeyRecord)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "deserialize signed pre-key", err)
	}
	return rec, nil
}

func (s *DAOSignedPreKeyStore) LoadSignedPreKeys() ([]*sessionrecord.SignedPreKey, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	results, err := s.dao.Find(ctx).Execute()
	if err != nil {
		return nil, err
	}
	var out []*sessionrecord.SignedPreKey
	for _, e := range results {
		if len(e.Record) == 0 {
			continue
		}
		rec, err := sessionrecord.NewSignedPreKeyFromBytes(e.Record, s.serializer.SignedPreKeyRecord)
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "deserialize signed pre-key", err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func (s *DAOSignedPreKeyStore) StoreSignedPreKey(signedPreKeyID uint32, rec *sessionrecord.SignedPreKey) error {
	ctx, cancel := newDaoCtx()
	defer cancel()

	data, err := rec.Serialize()
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "serialize signed pre-key", err)
	}

	existing, lookupErr := s.dao.QueryOneByIndex(ctx, "KeyID", signedPreKeyID)
	if lookupErr == nil && existing != nil {
		existing.Record = data
		return s.dao.Save(ctx, existing)
	}

	entity := &entities.SignedPreKeyEntity{
		KeyID:  signedPreKeyID,
		Record: data,
	}
	return s.dao.Save(ctx, entity)
}

func (s *DAOSignedPreKeyStore) ContainsSignedPreKey(signedPreKeyID uint32) (bool, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	_, err := s.dao.QueryOneByIndex(ctx, "KeyID", signedPreKeyID)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (s *DAOSignedPreKeyStore) RemoveSignedPreKey(signedPreKeyID uint32) error {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "KeyID", signedPreKeyID)
	if err != nil || entity == nil {
		return nil
	}
	return s.dao.Delete(ctx, entity)
}

// ---------------------------------------------------------------------------
// Identity Key Store
// ---------------------------------------------------------------------------

// DAOIdentityKeyStore implements store.IdentityKey using a GenericDAO.
type DAOIdentityKeyStore struct {
	mu             sync.RWMutex
	dao            qrdbdao.GenericDAO[*entities.IdentityKeyEntity]
	localIdentity  *identity.KeyPair
	registrationID uint32
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

func (s *DAOIdentityKeyStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) (store.IdentityChange, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	key := daoAddressKey(address)
	keyBytes := identityKey.Serialize()

	existing, lookupErr := s.dao.QueryOneByIndex(ctx, "Address", key)
	if lookupErr == nil && existing != nil {
		change := store.IdentityChangeNewOrUnchanged
		if !bytes.Equal(existing.Key, keyBytes) {
			change = store.IdentityChangeReplacedExisting
		}
		existing.Key = keyBytes
		if err := s.dao.Save(ctx, existing); err != nil {
			return store.IdentityChangeNewOrUnchanged, err
		}
		return change, nil
	}

	entity := &entities.IdentityKeyEntity{
		Address:        key,
		Key:            keyBytes,
		FirstUse:       time.Now().UnixMilli(),
		VerifiedStatus: 0,
	}
	if err := s.dao.Save(ctx, entity); err != nil {
		return store.IdentityChangeNewOrUnchanged, err
	}
	return store.IdentityChangeNewOrUnchanged, nil
}

func (s *DAOIdentityKeyStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, direction store.Direction) (bool, error) {
	ctx, cancel := newDaoCtx()
	defer cancel()
	entity, err := s.dao.QueryOneByIndex(ctx, "Address", daoAddressKey(address))
	if err != nil {
		// Trust on first use: no stored identity means trust.
		return true, nil
	}
	storedKey, err := ecc.DecodePoint(entity.Key, 0)
	if err != nil {
		return false, signalerrors.Wrap(signalerrors.ErrInternal, "decode stored identity key", err)
	}
	return identity.NewKey(storedKey).Fingerprint() == identityKey.Fingerprint(), nil
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
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "decode identity key", err)
	}
	key := identity.NewKey(pubKey)
	return key, nil
}

// ---------------------------------------------------------------------------
// Sender Key Store
// ---------------------------------------------------------------------------

// DAOSenderKeyStore implements groupstore.SenderKey using a GenericDAO.
// Records are serialized with the protobuf serializer so all internal state
// is preserved across restarts.
type DAOSenderKeyStore struct {
	dao        qrdbdao.GenericDAO[*entities.SenderKeyEntity]
	serializer *serialize.Serializer
}

// NewDAOSenderKeyStore creates a sender-key store backed by the DAO factory.
// It uses the protobuf serializer for wire-safe binary storage of SenderKey
// records, which contain only unexported fields and cannot be JSON-marshaled.
func NewDAOSenderKeyStore(f *daostore.Factory) *DAOSenderKeyStore {
	return &DAOSenderKeyStore{
		dao:        f.SenderKeys,
		serializer: serialize.NewProtobufSerializer(),
	}
}

func (s *DAOSenderKeyStore) StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *record.SenderKey) error {
	ctx, cancel := newDaoCtx()
	defer cancel()
	name := daoSenderKeyNameStr(senderKeyName)
	data, err := keyRecord.Serialize()
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
	rec, err := record.NewSenderKeyFromBytes(entity.Record,
		s.serializer.SenderKeyRecord, s.serializer.SenderKeyState)
	if err != nil {
		return nil, err
	}
	return rec, nil
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
	_ store.Session        = (*DAOSessionStore)(nil)
	_ store.PreKey         = (*DAOPreKeyStore)(nil)
	_ store.SignedPreKey   = (*DAOSignedPreKeyStore)(nil)
	_ store.IdentityKey    = (*DAOIdentityKeyStore)(nil)
	_ groupstore.SenderKey = (*DAOSenderKeyStore)(nil)
)
