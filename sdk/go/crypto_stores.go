package signal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
)

// addressKey returns a stable string key for a SignalAddress.
func addressKey(addr *protocol.SignalAddress) string {
	return fmt.Sprintf("%s_%d", addr.Name(), addr.DeviceID())
}

// =============================================================================
// Session Store
// =============================================================================

type fileSessionStore struct {
	mu         sync.RWMutex
	dir        string
	sessions   map[string]*record.Session
	serializer *serialize.Serializer
}

func newFileSessionStore(dir string, serializer *serialize.Serializer) (*fileSessionStore, error) {
	sessDir := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(sessDir, 0700); err != nil {
		return nil, err
	}
	s := &fileSessionStore{
		dir:        sessDir,
		sessions:   make(map[string]*record.Session),
		serializer: serializer,
	}
	// Load existing sessions from disk.
	entries, _ := os.ReadDir(sessDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sessDir, e.Name()))
		if err != nil {
			continue
		}
		sess, err := record.NewSessionFromBytes(data, serializer.Session, serializer.State)
		if err != nil {
			continue
		}
		key := strings.TrimSuffix(e.Name(), ".bin")
		s.sessions[key] = sess
	}
	return s, nil
}

func (s *fileSessionStore) path(key string) string {
	return filepath.Join(s.dir, key+".bin")
}

func (s *fileSessionStore) LoadSession(address *protocol.SignalAddress) *record.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := addressKey(address)
	if sess, ok := s.sessions[key]; ok {
		return sess
	}
	sess := record.NewSession(s.serializer.Session, s.serializer.State)
	return sess
}

func (s *fileSessionStore) StoreSession(address *protocol.SignalAddress, sess *record.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := addressKey(address)
	s.sessions[key] = sess
	if data, err := sess.Serialize(); err == nil {
		_ = os.WriteFile(s.path(key), data, 0600)
	}
}

func (s *fileSessionStore) ContainsSession(address *protocol.SignalAddress) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.sessions[addressKey(address)]
	return ok
}

func (s *fileSessionStore) GetSubDeviceSessions(name string) []uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var ids []uint32
	for k := range s.sessions {
		parts := strings.SplitN(k, "_", 2)
		if len(parts) == 2 && parts[0] == name {
			if id, err := strconv.ParseUint(parts[1], 10, 32); err == nil && id != 1 {
				ids = append(ids, uint32(id))
			}
		}
	}
	return ids
}

func (s *fileSessionStore) DeleteSession(address *protocol.SignalAddress) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := addressKey(address)
	delete(s.sessions, key)
	_ = os.Remove(s.path(key))
}

func (s *fileSessionStore) DeleteAllSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.sessions {
		_ = os.Remove(s.path(k))
	}
	s.sessions = make(map[string]*record.Session)
}

// =============================================================================
// PreKey Store
// =============================================================================

type filePreKeyStore struct {
	mu    sync.RWMutex
	dir   string
	store map[uint32]*record.PreKey
}

func newFilePreKeyStore(dir string) (*filePreKeyStore, error) {
	pkDir := filepath.Join(dir, "prekeys")
	if err := os.MkdirAll(pkDir, 0700); err != nil {
		return nil, err
	}
	return &filePreKeyStore{
		dir:   pkDir,
		store: make(map[uint32]*record.PreKey),
	}, nil
}

func (s *filePreKeyStore) LoadPreKey(preKeyID uint32) *record.PreKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.store[preKeyID]
}

func (s *filePreKeyStore) StorePreKey(preKeyID uint32, preKeyRecord *record.PreKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[preKeyID] = preKeyRecord
}

func (s *filePreKeyStore) ContainsPreKey(preKeyID uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.store[preKeyID]
	return ok
}

func (s *filePreKeyStore) RemovePreKey(preKeyID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, preKeyID)
}

// =============================================================================
// Signed PreKey Store
// =============================================================================

type fileSignedPreKeyStore struct {
	mu    sync.RWMutex
	dir   string
	store map[uint32]*record.SignedPreKey
}

func newFileSignedPreKeyStore(dir string) (*fileSignedPreKeyStore, error) {
	spkDir := filepath.Join(dir, "signed_prekeys")
	if err := os.MkdirAll(spkDir, 0700); err != nil {
		return nil, err
	}
	return &fileSignedPreKeyStore{
		dir:   spkDir,
		store: make(map[uint32]*record.SignedPreKey),
	}, nil
}

func (s *fileSignedPreKeyStore) LoadSignedPreKey(signedPreKeyID uint32) *record.SignedPreKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.store[signedPreKeyID]
}

func (s *fileSignedPreKeyStore) LoadSignedPreKeys() []*record.SignedPreKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []*record.SignedPreKey
	for _, k := range s.store {
		keys = append(keys, k)
	}
	return keys
}

func (s *fileSignedPreKeyStore) StoreSignedPreKey(signedPreKeyID uint32, rec *record.SignedPreKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[signedPreKeyID] = rec
}

func (s *fileSignedPreKeyStore) ContainsSignedPreKey(signedPreKeyID uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.store[signedPreKeyID]
	return ok
}

func (s *fileSignedPreKeyStore) RemoveSignedPreKey(signedPreKeyID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, signedPreKeyID)
}

// =============================================================================
// Identity Key Store
// =============================================================================

type identityData struct {
	Fingerprint string `json:"fingerprint"`
	KeyBytes    []byte `json:"key"`
}

type fileIdentityStore struct {
	mu              sync.RWMutex
	dir             string
	identityKeyPair *identity.KeyPair
	registrationID  uint32
	trustedKeys     map[string]*identity.Key // addressKey → identity key
}

func newFileIdentityStore(dir string, keyPair *identity.KeyPair, regID uint32) (*fileIdentityStore, error) {
	idDir := filepath.Join(dir, "identity_keys")
	if err := os.MkdirAll(idDir, 0700); err != nil {
		return nil, err
	}
	s := &fileIdentityStore{
		dir:             idDir,
		identityKeyPair: keyPair,
		registrationID:  regID,
		trustedKeys:     make(map[string]*identity.Key),
	}
	// Load trusted keys from disk.
	entries, _ := os.ReadDir(idDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(idDir, e.Name()))
		if err != nil {
			continue
		}
		var id identityData
		if err := json.Unmarshal(data, &id); err != nil || len(id.KeyBytes) == 0 {
			continue
		}
		// Reconstruct identity.Key from serialized bytes would require
		// ECC deserialization — for now, store fingerprint for trust checking.
		key := strings.TrimSuffix(e.Name(), ".json")
		_ = key
	}
	return s, nil
}

func (s *fileIdentityStore) GetIdentityKeyPair() *identity.KeyPair {
	return s.identityKeyPair
}

func (s *fileIdentityStore) GetLocalRegistrationId() uint32 {
	return s.registrationID
}

func (s *fileIdentityStore) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := addressKey(address)
	s.trustedKeys[key] = identityKey
	// Persist.
	data, _ := json.Marshal(identityData{
		Fingerprint: fmt.Sprintf("%x", identityKey.Fingerprint()),
		KeyBytes:    identityKey.Serialize(),
	})
	_ = os.WriteFile(filepath.Join(s.dir, key+".json"), data, 0600)
}

func (s *fileIdentityStore) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key, _ store.Direction) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	trusted, ok := s.trustedKeys[addressKey(address)]
	if !ok {
		return true // Trust on first use (TOFU).
	}
	return trusted.Fingerprint() == identityKey.Fingerprint()
}

func (s *fileIdentityStore) GetIdentity(address *protocol.SignalAddress) (*identity.Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.trustedKeys[addressKey(address)], nil
}

// =============================================================================
// Sender Key Store (for group messaging)
// =============================================================================

type fileSenderKeyStore struct {
	mu    sync.RWMutex
	dir   string
	store map[string]*groupRecord.SenderKey
}

func newFileSenderKeyStore(dir string) (*fileSenderKeyStore, error) {
	skDir := filepath.Join(dir, "sender_keys")
	if err := os.MkdirAll(skDir, 0700); err != nil {
		return nil, err
	}
	return &fileSenderKeyStore{
		dir:   skDir,
		store: make(map[string]*groupRecord.SenderKey),
	}, nil
}

func senderKeyNameKey(name *protocol.SenderKeyName) string {
	return fmt.Sprintf("%s_%s_%d", name.GroupID(), name.Sender().Name(), name.Sender().DeviceID())
}

func (s *fileSenderKeyStore) StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[senderKeyNameKey(senderKeyName)] = keyRecord
	return nil
}

func (s *fileSenderKeyStore) LoadSenderKey(senderKeyName *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.store[senderKeyNameKey(senderKeyName)], nil
}
