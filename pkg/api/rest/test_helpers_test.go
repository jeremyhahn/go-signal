package rest

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/certificates"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/devices"
	"github.com/jeremyhahn/go-signal/pkg/directory"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/keytransparency"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	"github.com/jeremyhahn/go-signal/pkg/securevaluerecovery"
	"github.com/jeremyhahn/go-signal/pkg/stickers"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

var errNoPreKeys = errors.New("no pre-keys available")

// --------------------------------------------------------------------------
// noopVerificationTransport is a VerificationTransport that captures sent
// codes so tests can retrieve and submit them.
// --------------------------------------------------------------------------

// noopVerificationTransport captures the last code sent per destination.
type noopVerificationTransport struct {
	mu    sync.Mutex
	codes map[string]string // destination -> last code
}

func newNoopVerificationTransport() *noopVerificationTransport {
	return &noopVerificationTransport{codes: make(map[string]string)}
}

func (t *noopVerificationTransport) SendCode(_ context.Context, destination, code string, _ ...verification.SendOption) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.codes[destination] = code
	return nil
}

func (t *noopVerificationTransport) Name() string { return "noop" }

// LastCode returns the most recently sent code for the given destination.
func (t *noopVerificationTransport) LastCode(destination string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.codes[destination]
}

// testAccountUUID is the UUID for the test account used across handlers.
const testAccountUUID = "11111111-1111-1111-1111-111111111111"

// testAccountNumber is the phone number for the test account.
const testAccountNumber = "+15551234567"

// testAuthToken is the auth token for the test account's primary device.
const testAuthToken = "test-auth-token-secret"

// testIdentityKey is a fixed identity key for testing (32 bytes).
var testIdentityKey = []byte("test-identity-key-32bytes-xxxxx")

// testIdentityKeyB64 is the base64-encoded identity key.
var testIdentityKeyB64 = base64.StdEncoding.EncodeToString(testIdentityKey)

// testSignedPreKeyPub is a fixed public key for the signed pre-key.
var testSignedPreKeyPub = []byte("signed-prekey-pub-32bytes-xxxxx")

// testSignedPreKeySig is a fixed signature for the signed pre-key.
var testSignedPreKeySig = []byte("signed-prekey-sig-64bytes-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

// testSignedPreKeyPubB64 is the base64-encoded signed pre-key public key.
var testSignedPreKeyPubB64 = base64.StdEncoding.EncodeToString(testSignedPreKeyPub)

// testSignedPreKeySigB64 is the base64-encoded signed pre-key signature.
var testSignedPreKeySigB64 = base64.StdEncoding.EncodeToString(testSignedPreKeySig)

// testPniIdentityKey is a fixed PNI identity key for testing.
var testPniIdentityKey = []byte("pni-identity-key-32bytes-xxxxxx")

// testPniIdentityKeyB64 is the base64-encoded PNI identity key.
var testPniIdentityKeyB64 = base64.StdEncoding.EncodeToString(testPniIdentityKey)

// --------------------------------------------------------------------------
// Real Signal key material for tests that exercise signature validation.
//
// Signal uses Curve25519 keys with XEdDSA signatures. The identity key is a
// 33-byte serialized Curve25519 public key (DJB type byte 0x05 + 32 bytes).
// Signed pre-keys carry an XEdDSA signature over the serialized public key.
// --------------------------------------------------------------------------

// signalKeyMaterial holds a complete set of real Curve25519 key pairs and
// corresponding valid XEdDSA signatures for use in tests.
type signalKeyMaterial struct {
	// ACI (Account Identity) key pair.
	ACIKeyPair *ecc.ECKeyPair
	// ACI identity key (33-byte serialized Curve25519 public key).
	ACIIdentityKey []byte
	// ACI identity key base64-encoded.
	ACIIdentityKeyB64 string

	// PNI (Phone Number Identity) key pair.
	PNIKeyPair *ecc.ECKeyPair
	// PNI identity key (33-byte serialized Curve25519 public key).
	PNIIdentityKey []byte
	// PNI identity key base64-encoded.
	PNIIdentityKeyB64 string

	// ACI signed pre-key (Curve25519) and its XEdDSA signature.
	ACISignedPreKeyPub    []byte // 33-byte serialized
	ACISignedPreKeySig    []byte // 64-byte XEdDSA signature
	ACISignedPreKeyPubB64 string
	ACISignedPreKeySigB64 string

	// PNI signed pre-key (Curve25519) and its XEdDSA signature.
	PNISignedPreKeyPub    []byte
	PNISignedPreKeySig    []byte
	PNISignedPreKeyPubB64 string
	PNISignedPreKeySigB64 string

	// ACI PQ last-resort pre-key (arbitrary bytes) and its XEdDSA signature.
	ACIPqPub    []byte
	ACIPqSig    []byte
	ACIPqPubB64 string
	ACIPqSigB64 string

	// PNI PQ last-resort pre-key (arbitrary bytes) and its XEdDSA signature.
	PNIPqPub    []byte
	PNIPqSig    []byte
	PNIPqPubB64 string
	PNIPqSigB64 string
}

var (
	testKeyMaterialOnce sync.Once
	testKeyMaterial     *signalKeyMaterial
)

// getTestKeyMaterial returns a lazily initialised, package-level set of real
// Curve25519 key pairs and XEdDSA signatures for use in handler tests that
// exercise signature validation. The keys are generated exactly once per test
// binary run.
func getTestKeyMaterial(t *testing.T) *signalKeyMaterial {
	t.Helper()
	testKeyMaterialOnce.Do(func() {
		m := &signalKeyMaterial{}

		// Generate ACI identity key pair.
		aciKP, err := ecc.GenerateKeyPair()
		if err != nil {
			panic("failed to generate ACI key pair: " + err.Error())
		}
		m.ACIKeyPair = aciKP
		m.ACIIdentityKey = aciKP.PublicKey().Serialize()
		m.ACIIdentityKeyB64 = base64.StdEncoding.EncodeToString(m.ACIIdentityKey)

		// Generate PNI identity key pair.
		pniKP, err := ecc.GenerateKeyPair()
		if err != nil {
			panic("failed to generate PNI key pair: " + err.Error())
		}
		m.PNIKeyPair = pniKP
		m.PNIIdentityKey = pniKP.PublicKey().Serialize()
		m.PNIIdentityKeyB64 = base64.StdEncoding.EncodeToString(m.PNIIdentityKey)

		// Generate ACI signed pre-key and sign it.
		aciSPKKP, err := ecc.GenerateKeyPair()
		if err != nil {
			panic("failed to generate ACI SPK key pair: " + err.Error())
		}
		m.ACISignedPreKeyPub = aciSPKKP.PublicKey().Serialize()
		aciSig, err := ecc.CalculateSignature(aciKP.PrivateKey(), m.ACISignedPreKeyPub)
		if err != nil {
			panic("failed to sign ACI SPK: " + err.Error())
		}
		m.ACISignedPreKeySig = aciSig[:]
		m.ACISignedPreKeyPubB64 = base64.StdEncoding.EncodeToString(m.ACISignedPreKeyPub)
		m.ACISignedPreKeySigB64 = base64.StdEncoding.EncodeToString(m.ACISignedPreKeySig)

		// Generate PNI signed pre-key and sign it.
		pniSPKKP, err := ecc.GenerateKeyPair()
		if err != nil {
			panic("failed to generate PNI SPK key pair: " + err.Error())
		}
		m.PNISignedPreKeyPub = pniSPKKP.PublicKey().Serialize()
		pniSig, err := ecc.CalculateSignature(pniKP.PrivateKey(), m.PNISignedPreKeyPub)
		if err != nil {
			panic("failed to sign PNI SPK: " + err.Error())
		}
		m.PNISignedPreKeySig = pniSig[:]
		m.PNISignedPreKeyPubB64 = base64.StdEncoding.EncodeToString(m.PNISignedPreKeyPub)
		m.PNISignedPreKeySigB64 = base64.StdEncoding.EncodeToString(m.PNISignedPreKeySig)

		// ACI PQ last-resort pre-key: arbitrary public key signed with ACI identity key.
		m.ACIPqPub = make([]byte, 32)
		for i := range m.ACIPqPub {
			m.ACIPqPub[i] = byte(i + 1)
		}
		aciPqSig, err := ecc.CalculateSignature(aciKP.PrivateKey(), m.ACIPqPub)
		if err != nil {
			panic("failed to sign ACI PQ key: " + err.Error())
		}
		m.ACIPqSig = aciPqSig[:]
		m.ACIPqPubB64 = base64.StdEncoding.EncodeToString(m.ACIPqPub)
		m.ACIPqSigB64 = base64.StdEncoding.EncodeToString(m.ACIPqSig)

		// PNI PQ last-resort pre-key: arbitrary public key signed with PNI identity key.
		m.PNIPqPub = make([]byte, 32)
		for i := range m.PNIPqPub {
			m.PNIPqPub[i] = byte(i + 33)
		}
		pniPqSig, err := ecc.CalculateSignature(pniKP.PrivateKey(), m.PNIPqPub)
		if err != nil {
			panic("failed to sign PNI PQ key: " + err.Error())
		}
		m.PNIPqSig = pniPqSig[:]
		m.PNIPqPubB64 = base64.StdEncoding.EncodeToString(m.PNIPqPub)
		m.PNIPqSigB64 = base64.StdEncoding.EncodeToString(m.PNIPqSig)

		testKeyMaterial = m
	})
	return testKeyMaterial
}

// newTestServerWithRealKeys creates a test server pre-populated with a test
// account whose identity key is a real Curve25519 public key. Use this helper
// for tests that exercise pre-key signature validation.
func newTestServerWithRealKeys(t *testing.T) (*Server, *accounts.Account, *signalKeyMaterial) {
	t.Helper()

	km := getTestKeyMaterial(t)
	s := newTestServer(t)

	acct := &accounts.Account{
		UUID:                   testAccountUUID,
		Number:                 testAccountNumber,
		IdentityKey:            km.ACIIdentityKey,
		PhoneNumberIdentityKey: km.PNIIdentityKey,
		UnidentifiedAccessKey:  []byte("unidentified-access-key-16byte"),
		Devices: []accounts.Device{
			{
				ID:        accounts.PrimaryDeviceID,
				Name:      "Test Phone",
				AuthToken: testAuthToken,
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: km.ACISignedPreKeyPub,
					Signature: km.ACISignedPreKeySig,
				},
				RegistrationID:  12345,
				CreatedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				LastSeen:        time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				FetchesMessages: true,
				Capabilities: accounts.DeviceCapabilities{
					Storage:  true,
					Transfer: true,
				},
			},
		},
		CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Version:   1,
	}

	if err := s.accounts.Create(context.Background(), acct); err != nil {
		t.Fatalf("failed to create test account with real keys: %v", err)
	}

	acct, err := s.accounts.Get(context.Background(), testAccountUUID)
	if err != nil {
		t.Fatalf("failed to get test account: %v", err)
	}

	// Store the signed pre-key.
	spk := &keys.SignedPreKey{
		KeyID:     1,
		PublicKey: km.ACISignedPreKeyPub,
		Signature: km.ACISignedPreKeySig,
	}
	if err := s.keys.StoreSignedPreKey(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, spk); err != nil {
		t.Fatalf("failed to store signed pre-key: %v", err)
	}

	return s, acct, km
}

// testLogger returns a silent slog.Logger for testing.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(noopWriter{}, nil))
}

type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }

// testAccount returns a fully populated test account with a primary device.
func testAccount() *accounts.Account {
	return &accounts.Account{
		UUID:                   testAccountUUID,
		Number:                 testAccountNumber,
		IdentityKey:            testIdentityKey,
		PhoneNumberIdentityKey: testPniIdentityKey,
		UnidentifiedAccessKey:  []byte("unidentified-access-key-16bytes"),
		Devices: []accounts.Device{
			{
				ID:        accounts.PrimaryDeviceID,
				Name:      "Test Phone",
				AuthToken: testAuthToken,
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: testSignedPreKeyPub,
					Signature: testSignedPreKeySig,
				},
				RegistrationID:  12345,
				CreatedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				LastSeen:        time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				FetchesMessages: true,
				Capabilities: accounts.DeviceCapabilities{
					Storage:  true,
					Transfer: true,
				},
			},
		},
		CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Version:   1,
	}
}

// newTestServer creates a Server instance backed by in-memory stores. The
// returned server has all managers wired up and is ready for handler testing
// via httptest. A no-op verification transport is used so no real SMS/SMTP
// calls are made; use newTestServerWithVerification to access sent codes.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, _ := newTestServerWithVerification(t)
	return s
}

// newTestServerWithVerification creates a test server and returns the
// noopVerificationTransport so tests can inspect and use the generated codes.
func newTestServerWithVerification(t *testing.T) (*Server, *noopVerificationTransport) {
	t.Helper()

	transport := newNoopVerificationTransport()
	store := verification.NewMemoryVerificationSessionStore()
	verificationMgr := verification.NewManager(store, transport, verification.ManagerConfig{
		CodeLength:  6,
		CodeTTL:     5 * time.Minute,
		MaxAttempts: 3,
	})

	logger := testLogger()

	accountStore := &memAccountStore{
		accounts: make(map[string]*accounts.Account),
		byNumber: make(map[string]string),
	}
	accountsMgr := accounts.NewAccountsManager(accountStore, 6)

	keyStore := &memPreKeyStore{
		signedPreKeys:       make(map[string]*keys.SignedPreKey),
		ecPreKeys:           make(map[string][]*keys.PreKey),
		kemPreKeys:          make(map[string][]*keys.KEMSignedPreKey),
		kemLastResortPreKey: make(map[string]*keys.KEMSignedPreKey),
	}
	keysMgr := keys.NewKeysManager(keyStore)

	msgStore := &memMessageStore{
		messages: make(map[string][]*messages.Envelope),
	}
	msgsMgr := messages.NewMessagesManager(msgStore)

	profileStore := &memProfileStore{
		profiles: make(map[string]*profiles.Profile),
		latest:   make(map[string]*profiles.Profile),
	}
	profilesMgr := profiles.NewProfilesManager(profileStore)

	stickersMgr := stickers.NewStickersManager(logger)
	directoryMgr := directory.NewDirectoryManager(logger)
	secureStorageMgr := securestorage.NewSecureStorageManager(logger)
	svrMgr := securevaluerecovery.NewSVRManager(logger)
	callingMgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider: &calling.StaticTurnProvider{
			URLs:     []string{"turn:turn.example.com:3478"},
			Hostname: "turn.example.com",
		},
		SurveyPublisher: calling.NewLogSurveyPublisher(logger),
		Logger:          logger,
	})
	ktMgr := keytransparency.NewKeyTransparencyManager(logger)
	captchaMgr := captcha.NewCaptchaManager(logger)
	certsMgr := certificates.NewCertificatesManager(secrets.NewSecureString("test-signing-key-32bytes-xxxxxx"), logger)

	usernameStore := &memUsernameStore{
		hashToUUID:   make(map[string]string),
		reservations: make(map[string]*usernames.UsernameReservation),
		links:        make(map[string]*usernames.UsernameLink),
		uuidToLink:   make(map[string]string),
		uuidToHash:   make(map[string][]byte),
	}
	usernamesMgr := usernames.NewUsernamesManager(usernameStore, logger)

	provStore := &memProvisioningStore{
		sessions: make(map[string]*devices.ProvisioningSession),
	}
	devicesMgr := devices.NewDevicesManager(provStore, accountsMgr, keysMgr, logger)

	s := NewServer(ServerConfig{
		Host:            "127.0.0.1",
		Port:            0,
		Logger:          logger,
		Accounts:        accountsMgr,
		Captcha:         captchaMgr,
		Certificates:    certsMgr,
		Keys:            keysMgr,
		Messages:        msgsMgr,
		Profiles:        profilesMgr,
		Stickers:        stickersMgr,
		Directory:       directoryMgr,
		SecureStorage:   secureStorageMgr,
		SVR:             svrMgr,
		Calling:         callingMgr,
		KeyTransparency: ktMgr,
		Usernames:       usernamesMgr,
		Devices:         devicesMgr,
		Verification:    verificationMgr,
	})
	return s, transport
}

// buildTestServerWithVerificationMgr creates a test server using the provided
// verification.Manager instead of creating a new one. All other managers are
// created with in-memory stores. It is used by tests that need to inject a
// custom-configured manager (e.g., with a very short session TTL).
func buildTestServerWithVerificationMgr(t *testing.T, verificationMgr *verification.Manager) *Server {
	t.Helper()

	logger := testLogger()

	accountStore := &memAccountStore{
		accounts: make(map[string]*accounts.Account),
		byNumber: make(map[string]string),
	}
	accountsMgr := accounts.NewAccountsManager(accountStore, 6)

	keyStore := &memPreKeyStore{
		signedPreKeys:       make(map[string]*keys.SignedPreKey),
		ecPreKeys:           make(map[string][]*keys.PreKey),
		kemPreKeys:          make(map[string][]*keys.KEMSignedPreKey),
		kemLastResortPreKey: make(map[string]*keys.KEMSignedPreKey),
	}
	keysMgr := keys.NewKeysManager(keyStore)

	msgStore := &memMessageStore{
		messages: make(map[string][]*messages.Envelope),
	}
	msgsMgr := messages.NewMessagesManager(msgStore)

	profileStore := &memProfileStore{
		profiles: make(map[string]*profiles.Profile),
		latest:   make(map[string]*profiles.Profile),
	}
	profilesMgr := profiles.NewProfilesManager(profileStore)

	stickersMgr := stickers.NewStickersManager(logger)
	directoryMgr := directory.NewDirectoryManager(logger)
	secureStorageMgr := securestorage.NewSecureStorageManager(logger)
	svrMgr := securevaluerecovery.NewSVRManager(logger)
	callingMgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider: &calling.StaticTurnProvider{
			URLs:     []string{"turn:turn.example.com:3478"},
			Hostname: "turn.example.com",
		},
		SurveyPublisher: calling.NewLogSurveyPublisher(logger),
		Logger:          logger,
	})
	ktMgr := keytransparency.NewKeyTransparencyManager(logger)
	captchaMgr := captcha.NewCaptchaManager(logger)
	certsMgr := certificates.NewCertificatesManager(secrets.NewSecureString("test-signing-key-32bytes-xxxxxx"), logger)

	usernameStore := &memUsernameStore{
		hashToUUID:   make(map[string]string),
		reservations: make(map[string]*usernames.UsernameReservation),
		links:        make(map[string]*usernames.UsernameLink),
		uuidToLink:   make(map[string]string),
		uuidToHash:   make(map[string][]byte),
	}
	usernamesMgr := usernames.NewUsernamesManager(usernameStore, logger)

	provStore := &memProvisioningStore{
		sessions: make(map[string]*devices.ProvisioningSession),
	}
	devicesMgr := devices.NewDevicesManager(provStore, accountsMgr, keysMgr, logger)

	return NewServer(ServerConfig{
		Host:            "127.0.0.1",
		Port:            0,
		Logger:          logger,
		Accounts:        accountsMgr,
		Captcha:         captchaMgr,
		Certificates:    certsMgr,
		Keys:            keysMgr,
		Messages:        msgsMgr,
		Profiles:        profilesMgr,
		Stickers:        stickersMgr,
		Directory:       directoryMgr,
		SecureStorage:   secureStorageMgr,
		SVR:             svrMgr,
		Calling:         callingMgr,
		KeyTransparency: ktMgr,
		Usernames:       usernamesMgr,
		Devices:         devicesMgr,
		Verification:    verificationMgr,
	})
}

// newTestServerWithAccount creates a test server and pre-populates it with a
// test account. Returns the server and the created account.
func newTestServerWithAccount(t *testing.T) (*Server, *accounts.Account) {
	t.Helper()

	s := newTestServer(t)
	acct := testAccount()

	if err := s.accounts.Create(context.Background(), acct); err != nil {
		t.Fatalf("failed to create test account: %v", err)
	}

	// Re-fetch to get proper timestamps set by manager.
	acct, err := s.accounts.Get(context.Background(), testAccountUUID)
	if err != nil {
		t.Fatalf("failed to get test account: %v", err)
	}

	// Store a signed pre-key for the primary device.
	spk := &keys.SignedPreKey{
		KeyID:     1,
		PublicKey: testSignedPreKeyPub,
		Signature: testSignedPreKeySig,
	}
	if err := s.keys.StoreSignedPreKey(context.Background(), testAccountUUID, accounts.PrimaryDeviceID, spk); err != nil {
		t.Fatalf("failed to store signed pre-key: %v", err)
	}

	return s, acct
}

// --------------------------------------------------------------------------
// In-memory AccountStore
// --------------------------------------------------------------------------

type memAccountStore struct {
	mu       sync.RWMutex
	accounts map[string]*accounts.Account
	byNumber map[string]string // number -> uuid
}

func (s *memAccountStore) Create(_ context.Context, account *accounts.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.accounts[account.UUID]; exists {
		return &accounts.AccountAlreadyExistsError{Identifier: account.UUID}
	}
	clone := *account
	clone.Devices = make([]accounts.Device, len(account.Devices))
	copy(clone.Devices, account.Devices)
	s.accounts[account.UUID] = &clone
	if account.Number != "" {
		s.byNumber[account.Number] = account.UUID
	}
	return nil
}

func (s *memAccountStore) Get(_ context.Context, uuid string) (*accounts.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	acct, ok := s.accounts[uuid]
	if !ok {
		return nil, &accounts.AccountNotFoundError{Identifier: uuid}
	}
	clone := *acct
	clone.Devices = make([]accounts.Device, len(acct.Devices))
	copy(clone.Devices, acct.Devices)
	return &clone, nil
}

func (s *memAccountStore) GetByNumber(_ context.Context, number string) (*accounts.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uuid, ok := s.byNumber[number]
	if !ok {
		return nil, &accounts.AccountNotFoundError{Identifier: number}
	}
	acct := s.accounts[uuid]
	clone := *acct
	clone.Devices = make([]accounts.Device, len(acct.Devices))
	copy(clone.Devices, acct.Devices)
	return &clone, nil
}

func (s *memAccountStore) Update(_ context.Context, account *accounts.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[account.UUID]; !ok {
		return &accounts.AccountNotFoundError{Identifier: account.UUID}
	}
	clone := *account
	clone.Devices = make([]accounts.Device, len(account.Devices))
	copy(clone.Devices, account.Devices)
	s.accounts[account.UUID] = &clone
	if account.Number != "" {
		s.byNumber[account.Number] = account.UUID
	}
	return nil
}

func (s *memAccountStore) Delete(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	acct, ok := s.accounts[uuid]
	if !ok {
		return &accounts.AccountNotFoundError{Identifier: uuid}
	}
	delete(s.byNumber, acct.Number)
	delete(s.accounts, uuid)
	return nil
}

// --------------------------------------------------------------------------
// In-memory PreKeyStore
// --------------------------------------------------------------------------

type memPreKeyStore struct {
	mu                  sync.RWMutex
	signedPreKeys       map[string]*keys.SignedPreKey
	ecPreKeys           map[string][]*keys.PreKey
	kemPreKeys          map[string][]*keys.KEMSignedPreKey
	kemLastResortPreKey map[string]*keys.KEMSignedPreKey
}

func keyPrefix(uuid string, deviceID uint64) string {
	return uuid + ":" + string(rune(deviceID))
}

func (s *memPreKeyStore) StoreECPreKeys(_ context.Context, uuid string, deviceID uint64, preKeys []*keys.PreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyPrefix(uuid, deviceID)
	s.ecPreKeys[k] = append(s.ecPreKeys[k], preKeys...)
	return nil
}

func (s *memPreKeyStore) StoreKEMPreKeys(_ context.Context, uuid string, deviceID uint64, preKeys []*keys.KEMSignedPreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyPrefix(uuid, deviceID)
	s.kemPreKeys[k] = append(s.kemPreKeys[k], preKeys...)
	return nil
}

func (s *memPreKeyStore) StoreKEMLastResortPreKey(_ context.Context, uuid string, deviceID uint64, preKey *keys.KEMSignedPreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *preKey
	clone.IsLastResort = true
	s.kemLastResortPreKey[keyPrefix(uuid, deviceID)] = &clone
	return nil
}

func (s *memPreKeyStore) StoreSignedPreKey(_ context.Context, uuid string, deviceID uint64, signedPreKey *keys.SignedPreKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signedPreKeys[keyPrefix(uuid, deviceID)] = signedPreKey
	return nil
}

func (s *memPreKeyStore) TakeEC(_ context.Context, uuid string, deviceID uint64) (*keys.PreKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyPrefix(uuid, deviceID)
	pks := s.ecPreKeys[k]
	if len(pks) == 0 {
		return nil, errNoPreKeys
	}
	pk := pks[0]
	s.ecPreKeys[k] = pks[1:]
	return pk, nil
}

func (s *memPreKeyStore) TakeKEM(_ context.Context, uuid string, deviceID uint64) (*keys.KEMSignedPreKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyPrefix(uuid, deviceID)
	pks := s.kemPreKeys[k]
	if len(pks) == 0 {
		return nil, errNoPreKeys
	}
	pk := pks[0]
	s.kemPreKeys[k] = pks[1:]
	return pk, nil
}

func (s *memPreKeyStore) GetKEMLastResortPreKey(_ context.Context, uuid string, deviceID uint64) (*keys.KEMSignedPreKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pk, ok := s.kemLastResortPreKey[keyPrefix(uuid, deviceID)]
	if !ok {
		return nil, errNoPreKeys
	}
	return pk, nil
}

func (s *memPreKeyStore) GetSignedPreKey(_ context.Context, uuid string, deviceID uint64) (*keys.SignedPreKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	spk, ok := s.signedPreKeys[keyPrefix(uuid, deviceID)]
	if !ok {
		return nil, &accounts.DeviceNotFoundError{AccountUUID: uuid, DeviceID: deviceID}
	}
	return spk, nil
}

func (s *memPreKeyStore) GetPreKeyCount(_ context.Context, uuid string, deviceID uint64) (*keys.PreKeyState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k := keyPrefix(uuid, deviceID)
	_, hasLastResort := s.kemLastResortPreKey[k]
	return &keys.PreKeyState{
		ECCount:       len(s.ecPreKeys[k]),
		KEMCount:      len(s.kemPreKeys[k]),
		HasLastResort: hasLastResort,
	}, nil
}

func (s *memPreKeyStore) DeleteAllForDevice(_ context.Context, uuid string, deviceID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := keyPrefix(uuid, deviceID)
	delete(s.signedPreKeys, k)
	delete(s.ecPreKeys, k)
	delete(s.kemPreKeys, k)
	delete(s.kemLastResortPreKey, k)
	return nil
}

func (s *memPreKeyStore) DeleteAllForAccount(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.signedPreKeys {
		if len(k) > len(uuid) && k[:len(uuid)] == uuid {
			delete(s.signedPreKeys, k)
		}
	}
	for k := range s.ecPreKeys {
		if len(k) > len(uuid) && k[:len(uuid)] == uuid {
			delete(s.ecPreKeys, k)
		}
	}
	for k := range s.kemPreKeys {
		if len(k) > len(uuid) && k[:len(uuid)] == uuid {
			delete(s.kemPreKeys, k)
		}
	}
	for k := range s.kemLastResortPreKey {
		if len(k) > len(uuid) && k[:len(uuid)] == uuid {
			delete(s.kemLastResortPreKey, k)
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// In-memory MessageStore
// --------------------------------------------------------------------------

type memMessageStore struct {
	mu       sync.RWMutex
	messages map[string][]*messages.Envelope
	nextID   atomic.Uint64
}

func msgKey(uuid string, deviceID uint64) string {
	return uuid + ":" + string(rune(deviceID))
}

func (s *memMessageStore) Insert(_ context.Context, destinationUUID string, destinationDevice uint64, envelope *messages.Envelope) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextID.Add(1)
	envelope.ID = id
	k := msgKey(destinationUUID, destinationDevice)
	clone := *envelope
	s.messages[k] = append(s.messages[k], &clone)
	return id, nil
}

func (s *memMessageStore) GetMessagesForDevice(_ context.Context, destinationUUID string, destinationDevice uint64) ([]*messages.Envelope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k := msgKey(destinationUUID, destinationDevice)
	result := make([]*messages.Envelope, len(s.messages[k]))
	for i, env := range s.messages[k] {
		clone := *env
		result[i] = &clone
	}
	return result, nil
}

func (s *memMessageStore) Delete(_ context.Context, destinationUUID string, serverGUID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, envs := range s.messages {
		if len(k) < len(destinationUUID) {
			continue
		}
		for i, env := range envs {
			if env.ServerGUID == serverGUID {
				s.messages[k] = append(envs[:i], envs[i+1:]...)
				return nil
			}
		}
	}
	return nil
}

func (s *memMessageStore) DeleteForDevice(_ context.Context, destinationUUID string, destinationDevice uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.messages, msgKey(destinationUUID, destinationDevice))
	return nil
}

func (s *memMessageStore) DeleteForAccount(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.messages {
		if len(k) > len(uuid) && k[:len(uuid)] == uuid {
			delete(s.messages, k)
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// In-memory ProfileStore
// --------------------------------------------------------------------------

type memProfileStore struct {
	mu       sync.RWMutex
	profiles map[string]*profiles.Profile // uuid:version -> profile
	latest   map[string]*profiles.Profile // uuid -> latest profile
}

func profileKey(uuid, version string) string {
	return uuid + ":" + version
}

func (s *memProfileStore) Set(_ context.Context, profile *profiles.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *profile
	s.profiles[profileKey(profile.UUID, profile.Version)] = &clone
	s.latest[profile.UUID] = &clone
	return nil
}

func (s *memProfileStore) Get(_ context.Context, uuid, version string) (*profiles.Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[profileKey(uuid, version)]
	if !ok {
		return nil, &profiles.ProfileNotFoundError{UUID: uuid, Version: version}
	}
	clone := *p
	return &clone, nil
}

func (s *memProfileStore) GetLatest(_ context.Context, uuid string) (*profiles.Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.latest[uuid]
	if !ok {
		return nil, &profiles.ProfileNotFoundError{UUID: uuid}
	}
	clone := *p
	return &clone, nil
}

func (s *memProfileStore) Delete(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.latest, uuid)
	for k := range s.profiles {
		if len(k) > len(uuid) && k[:len(uuid)] == uuid {
			delete(s.profiles, k)
		}
	}
	return nil
}

// --------------------------------------------------------------------------
// In-memory UsernameStore
// --------------------------------------------------------------------------

type memUsernameStore struct {
	mu           sync.RWMutex
	hashToUUID   map[string]string                         // hex(hash) -> uuid
	reservations map[string]*usernames.UsernameReservation // uuid -> reservation
	links        map[string]*usernames.UsernameLink        // handle -> link
	uuidToLink   map[string]string                         // uuid -> handle
	uuidToHash   map[string][]byte                         // uuid -> confirmed hash
}

func hashKey(h []byte) string {
	return base64.StdEncoding.EncodeToString(h)
}

func (s *memUsernameStore) ReserveHash(_ context.Context, uuid string, hashes [][]byte) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, h := range hashes {
		k := hashKey(h)
		if _, taken := s.hashToUUID[k]; !taken {
			token := "reservation-token-" + uuid
			s.reservations[uuid] = &usernames.UsernameReservation{
				UUID:             uuid,
				UsernameHashes:   [][]byte{h},
				ReservationToken: token,
				ExpiresAt:        time.Now().Add(5 * time.Minute),
			}
			return h, token, nil
		}
	}
	return nil, "", &usernames.UsernameHashConflictError{Hash: hashes[0]}
}

func (s *memUsernameStore) ConfirmHash(_ context.Context, uuid string, hash []byte, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, ok := s.reservations[uuid]
	if !ok || res.ReservationToken != token {
		return &usernames.InvalidReservationTokenError{UUID: uuid}
	}
	k := hashKey(hash)
	s.hashToUUID[k] = uuid
	s.uuidToHash[uuid] = hash
	delete(s.reservations, uuid)
	return nil
}

func (s *memUsernameStore) LookupByHash(_ context.Context, hash []byte) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	uuid, ok := s.hashToUUID[hashKey(hash)]
	if !ok {
		return "", &usernames.UsernameNotFoundError{Hash: hash}
	}
	return uuid, nil
}

func (s *memUsernameStore) DeleteHash(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.uuidToHash[uuid]
	if !ok {
		return &usernames.UsernameNotFoundError{}
	}
	delete(s.hashToUUID, hashKey(h))
	delete(s.uuidToHash, uuid)
	return nil
}

func (s *memUsernameStore) SetLink(_ context.Context, link *usernames.UsernameLink) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Remove old link if exists
	if oldHandle, ok := s.uuidToLink[link.UUID]; ok {
		delete(s.links, oldHandle)
	}
	clone := *link
	s.links[link.UsernameLinkHandle] = &clone
	s.uuidToLink[link.UUID] = link.UsernameLinkHandle
	return nil
}

func (s *memUsernameStore) GetLink(_ context.Context, handle string) (*usernames.UsernameLink, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	link, ok := s.links[handle]
	if !ok {
		return nil, &usernames.UsernameLinkNotFoundError{Handle: handle}
	}
	clone := *link
	return &clone, nil
}

func (s *memUsernameStore) DeleteLink(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	handle, ok := s.uuidToLink[uuid]
	if !ok {
		return &usernames.UsernameLinkNotFoundError{Handle: uuid}
	}
	delete(s.links, handle)
	delete(s.uuidToLink, uuid)
	return nil
}

// --------------------------------------------------------------------------
// In-memory ProvisioningStore
// --------------------------------------------------------------------------

type memProvisioningStore struct {
	mu       sync.RWMutex
	sessions map[string]*devices.ProvisioningSession
}

func (s *memProvisioningStore) StoreSession(_ context.Context, session *devices.ProvisioningSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *session
	s.sessions[session.Code] = &clone
	return nil
}

func (s *memProvisioningStore) GetSession(_ context.Context, code string) (*devices.ProvisioningSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[code]
	if !ok {
		return nil, &devices.InvalidProvisioningCodeError{Code: code}
	}
	clone := *session
	return &clone, nil
}

func (s *memProvisioningStore) DeleteSession(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, code)
	return nil
}
