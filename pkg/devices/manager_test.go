package devices

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// mockProvisioningStore is a test double for ProvisioningStore.
type mockProvisioningStore struct {
	sessions     map[string]*ProvisioningSession
	storeErr     error
	getErr       error
	deleteErr    error
	deleteCalled map[string]int
}

func newMockProvisioningStore() *mockProvisioningStore {
	return &mockProvisioningStore{
		sessions:     make(map[string]*ProvisioningSession),
		deleteCalled: make(map[string]int),
	}
}

func (m *mockProvisioningStore) StoreSession(_ context.Context, session *ProvisioningSession) error {
	if m.storeErr != nil {
		return m.storeErr
	}
	clone := *session
	m.sessions[session.Code] = &clone
	return nil
}

func (m *mockProvisioningStore) GetSession(_ context.Context, code string) (*ProvisioningSession, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	s, ok := m.sessions[code]
	if !ok {
		return nil, &InvalidProvisioningCodeError{Code: code}
	}
	clone := *s
	return &clone, nil
}

func (m *mockProvisioningStore) DeleteSession(_ context.Context, code string) error {
	m.deleteCalled[code]++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.sessions, code)
	return nil
}

// mockAccountsManager wraps a real AccountsManager backed by in-memory state.
// We use a real AccountsManager with a mockAccountStore to control behavior.
type mockAccountStore struct {
	accounts map[string]*accounts.Account
	storeErr error
	getErr   error
	updErr   error
}

func newMockAccountStore() *mockAccountStore {
	return &mockAccountStore{
		accounts: make(map[string]*accounts.Account),
	}
}

func (s *mockAccountStore) Create(_ context.Context, acct *accounts.Account) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	clone := *acct
	clone.Devices = make([]accounts.Device, len(acct.Devices))
	copy(clone.Devices, acct.Devices)
	s.accounts[acct.UUID] = &clone
	return nil
}

func (s *mockAccountStore) Get(_ context.Context, uuid string) (*accounts.Account, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	acct, ok := s.accounts[uuid]
	if !ok {
		return nil, &accounts.AccountNotFoundError{Identifier: uuid}
	}
	clone := *acct
	clone.Devices = make([]accounts.Device, len(acct.Devices))
	copy(clone.Devices, acct.Devices)
	return &clone, nil
}

func (s *mockAccountStore) GetByNumber(_ context.Context, _ string) (*accounts.Account, error) {
	return nil, &accounts.AccountNotFoundError{Identifier: "not implemented"}
}

// GetByPNI is a stub; PNI routing is not exercised by the devices tests.
func (s *mockAccountStore) GetByPNI(_ context.Context, pni string) (*accounts.Account, error) {
	return nil, &accounts.AccountNotFoundError{Identifier: pni}
}

func (s *mockAccountStore) Update(_ context.Context, acct *accounts.Account) error {
	if s.updErr != nil {
		return s.updErr
	}
	clone := *acct
	clone.Devices = make([]accounts.Device, len(acct.Devices))
	copy(clone.Devices, acct.Devices)
	s.accounts[acct.UUID] = &clone
	return nil
}

func (s *mockAccountStore) Delete(_ context.Context, _ string) error {
	return nil
}

func (s *mockAccountStore) ListAll(_ context.Context, _ func(*accounts.Account) error) error {
	return nil
}

// mockPreKeyStore is a test double for keys.PreKeyStore.
type mockPreKeyStore struct {
	signedPreKeys  map[string]*keys.SignedPreKey
	storeSignedErr error
}

func newMockPreKeyStore() *mockPreKeyStore {
	return &mockPreKeyStore{
		signedPreKeys: make(map[string]*keys.SignedPreKey),
	}
}

func (s *mockPreKeyStore) StoreECPreKeys(_ context.Context, _ string, _ uint64, _ []*keys.PreKey) error {
	return nil
}

func (s *mockPreKeyStore) StoreKEMPreKeys(_ context.Context, _ string, _ uint64, _ []*keys.KEMSignedPreKey) error {
	return nil
}

func (s *mockPreKeyStore) StoreSignedPreKey(_ context.Context, uuid string, deviceID uint64, spk *keys.SignedPreKey) error {
	if s.storeSignedErr != nil {
		return s.storeSignedErr
	}
	key := uuid + ":" + string(rune(deviceID))
	s.signedPreKeys[key] = spk
	return nil
}

func (s *mockPreKeyStore) StoreKEMLastResortPreKey(_ context.Context, _ string, _ uint64, _ *keys.KEMSignedPreKey) error {
	return nil
}

func (s *mockPreKeyStore) TakeEC(_ context.Context, _ string, _ uint64) (*keys.PreKey, error) {
	return nil, nil
}

func (s *mockPreKeyStore) TakeKEM(_ context.Context, _ string, _ uint64) (*keys.KEMSignedPreKey, error) {
	return nil, nil
}

func (s *mockPreKeyStore) GetKEMLastResortPreKey(_ context.Context, _ string, _ uint64) (*keys.KEMSignedPreKey, error) {
	return nil, nil
}

func (s *mockPreKeyStore) GetSignedPreKey(_ context.Context, _ string, _ uint64) (*keys.SignedPreKey, error) {
	return nil, nil
}

func (s *mockPreKeyStore) GetPreKeyCount(_ context.Context, _ string, _ uint64) (*keys.PreKeyState, error) {
	return &keys.PreKeyState{}, nil
}

func (s *mockPreKeyStore) DeleteAllForDevice(_ context.Context, _ string, _ uint64) error {
	return nil
}

func (s *mockPreKeyStore) DeleteAllForAccount(_ context.Context, _ string) error {
	return nil
}

func (s *mockPreKeyStore) ListAccountUUIDs(_ context.Context) ([]string, error) {
	return nil, nil
}

func testLogger() *slog.Logger {
	return slog.Default()
}

func validSignedPreKeyEntity() SignedPreKeyEntity {
	return SignedPreKeyEntity{
		KeyId:     1,
		PublicKey: base64.StdEncoding.EncodeToString([]byte("test-public-key")),
		Signature: base64.StdEncoding.EncodeToString([]byte("test-signature")),
	}
}

func validLinkDeviceRequest(code string) *LinkDeviceRequest {
	return &LinkDeviceRequest{
		VerificationCode: code,
		AccountAttributes: DeviceAccountAttributes{
			FetchesMessages:   true,
			RegistrationId:    100,
			PniRegistrationId: 200,
			Name:              "test-device",
		},
		AciSignedPreKey: validSignedPreKeyEntity(),
		PniSignedPreKey: validSignedPreKeyEntity(),
	}
}

// --- NewDevicesManager tests ---

func TestNewDevicesManager(t *testing.T) {
	store := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keyStore := newMockPreKeyStore()
	keysMgr := keys.NewKeysManager(keyStore)

	mgr := NewDevicesManager(store, acctMgr, keysMgr, testLogger())
	if mgr == nil {
		t.Fatal("expected non-nil DevicesManager")
		return
	}
	if mgr.store != store {
		t.Fatal("expected store to be assigned")
	}
}

func TestNewDevicesManagerFieldsAssigned(t *testing.T) {
	store := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keyStore := newMockPreKeyStore()
	keysMgr := keys.NewKeysManager(keyStore)

	mgr := NewDevicesManager(store, acctMgr, keysMgr, testLogger())
	if mgr.accounts != acctMgr {
		t.Fatal("expected accounts manager to be assigned")
	}
	if mgr.keys != keysMgr {
		t.Fatal("expected keys manager to be assigned")
	}
	if mgr.logger == nil {
		t.Fatal("expected logger to be assigned")
	}
}

// --- CreateProvisioningCode tests ---

func TestCreateProvisioningCode_Success(t *testing.T) {
	store := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(store, acctMgr, keysMgr, testLogger())

	code, err := mgr.CreateProvisioningCode(context.Background(), "test-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code == nil {
		t.Fatal("expected non-nil provisioning code")
		return
	}
	if code.VerificationCode == "" {
		t.Fatal("expected non-empty verification code")
	}

	// Verify session was stored.
	if len(store.sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(store.sessions))
	}
}

func TestCreateProvisioningCode_UniqueCodesPerCall(t *testing.T) {
	store := newMockProvisioningStore()
	acctMgr := accounts.NewAccountsManager(newMockAccountStore(), 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(store, acctMgr, keysMgr, testLogger())

	code1, err := mgr.CreateProvisioningCode(context.Background(), "uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	code2, err := mgr.CreateProvisioningCode(context.Background(), "uuid-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code1.VerificationCode == code2.VerificationCode {
		t.Fatal("expected different verification codes for different calls")
	}
}

func TestCreateProvisioningCode_StoreError(t *testing.T) {
	store := newMockProvisioningStore()
	store.storeErr = errors.New("store failure")
	acctMgr := accounts.NewAccountsManager(newMockAccountStore(), 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(store, acctMgr, keysMgr, testLogger())

	code, err := mgr.CreateProvisioningCode(context.Background(), "test-uuid")
	if err == nil {
		t.Fatal("expected error when store fails")
	}
	if code != nil {
		t.Fatal("expected nil code on error")
	}
	if err.Error() != "store failure" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestCreateProvisioningCode_SessionExpiresInFuture(t *testing.T) {
	store := newMockProvisioningStore()
	acctMgr := accounts.NewAccountsManager(newMockAccountStore(), 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(store, acctMgr, keysMgr, testLogger())

	code, err := mgr.CreateProvisioningCode(context.Background(), "test-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Find the stored session.
	var session *ProvisioningSession
	for _, s := range store.sessions {
		session = s
		break
	}
	if session == nil {
		t.Fatal("expected session to be stored")
		return
	}
	if session.UUID != "test-uuid" {
		t.Fatalf("expected UUID %q, got %q", "test-uuid", session.UUID)
	}
	if session.Code != code.VerificationCode {
		t.Fatalf("expected session code to match verification code")
	}
	if !session.ExpiresAt.After(time.Now()) {
		t.Fatal("expected expiration to be in the future")
	}
	if session.ExpiresAt.After(time.Now().Add(11 * time.Minute)) {
		t.Fatal("expected expiration to be within ~10 minutes")
	}
}

// --- LinkDevice tests ---

func setupLinkDeviceTest(t *testing.T) (*DevicesManager, *mockProvisioningStore, *mockAccountStore, string) {
	t.Helper()

	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	// Create an account with a primary device.
	acctStore.accounts["test-uuid"] = &accounts.Account{
		UUID:        "test-uuid",
		Number:      "+15551234567",
		IdentityKey: []byte("identity-key"),
		Devices: []accounts.Device{
			{
				ID:        1,
				AuthToken: "primary-token",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte("pub"),
					Signature: []byte("sig"),
				},
			},
		},
	}

	// Create a provisioning code.
	code, err := mgr.CreateProvisioningCode(context.Background(), "test-uuid")
	if err != nil {
		t.Fatalf("failed to create provisioning code: %v", err)
	}

	return mgr, provStore, acctStore, code.VerificationCode
}

func TestLinkDevice_Success(t *testing.T) {
	mgr, _, acctStore, code := setupLinkDeviceTest(t)

	req := validLinkDeviceRequest(code)
	resp, err := mgr.LinkDevice(context.Background(), code, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
		return
	}
	if resp.DeviceId == 0 {
		t.Fatal("expected non-zero device ID")
	}

	// Verify account has 2 devices now.
	acct := acctStore.accounts["test-uuid"]
	if len(acct.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(acct.Devices))
	}
}

func TestLinkDevice_DeviceIDAssigned(t *testing.T) {
	mgr, _, _, code := setupLinkDeviceTest(t)

	req := validLinkDeviceRequest(code)
	resp, err := mgr.LinkDevice(context.Background(), code, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Primary device is ID 1, so new device should be ID 2.
	if resp.DeviceId != 2 {
		t.Fatalf("expected device ID 2, got %d", resp.DeviceId)
	}
}

func TestLinkDevice_InvalidCode(t *testing.T) {
	mgr, _, _, _ := setupLinkDeviceTest(t)

	req := validLinkDeviceRequest("nonexistent-code")
	resp, err := mgr.LinkDevice(context.Background(), "nonexistent-code", req)
	if err == nil {
		t.Fatal("expected error for invalid code")
	}
	if resp != nil {
		t.Fatal("expected nil response on error")
	}

	var invalidErr *InvalidProvisioningCodeError
	if !errors.As(err, &invalidErr) {
		t.Fatalf("expected *InvalidProvisioningCodeError, got %T", err)
	}
}

func TestLinkDevice_ExpiredCode(t *testing.T) {
	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	// Store an already-expired session.
	expiredSession := &ProvisioningSession{
		Code:      "expired-code",
		UUID:      "test-uuid",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	provStore.sessions["expired-code"] = expiredSession

	req := validLinkDeviceRequest("expired-code")
	resp, err := mgr.LinkDevice(context.Background(), "expired-code", req)
	if err == nil {
		t.Fatal("expected error for expired code")
	}
	if resp != nil {
		t.Fatal("expected nil response on error")
	}

	var expiredErr *ProvisioningCodeExpiredError
	if !errors.As(err, &expiredErr) {
		t.Fatalf("expected *ProvisioningCodeExpiredError, got %T", err)
	}

	// Expired session should trigger delete attempt.
	if provStore.deleteCalled["expired-code"] < 1 {
		t.Fatal("expected delete to be called for expired session")
	}
}

func TestLinkDevice_ExpiredCodeDeleteFailure(t *testing.T) {
	provStore := newMockProvisioningStore()
	provStore.deleteErr = errors.New("delete failure")
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	expiredSession := &ProvisioningSession{
		Code:      "expired-code",
		UUID:      "test-uuid",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	provStore.sessions["expired-code"] = expiredSession

	req := validLinkDeviceRequest("expired-code")
	_, err := mgr.LinkDevice(context.Background(), "expired-code", req)

	// Should still return ProvisioningCodeExpiredError even if delete fails.
	var expiredErr *ProvisioningCodeExpiredError
	if !errors.As(err, &expiredErr) {
		t.Fatalf("expected *ProvisioningCodeExpiredError, got %T", err)
	}
}

func TestLinkDevice_InvalidBase64PublicKey(t *testing.T) {
	mgr, _, _, code := setupLinkDeviceTest(t)

	req := validLinkDeviceRequest(code)
	req.AciSignedPreKey.PublicKey = "!!!invalid-base64!!!"

	resp, err := mgr.LinkDevice(context.Background(), code, req)
	if err == nil {
		t.Fatal("expected error for invalid base64 public key")
	}
	if resp != nil {
		t.Fatal("expected nil response on error")
	}
}

func TestLinkDevice_InvalidBase64Signature(t *testing.T) {
	mgr, _, _, code := setupLinkDeviceTest(t)

	req := validLinkDeviceRequest(code)
	req.AciSignedPreKey.Signature = "!!!invalid-base64!!!"

	resp, err := mgr.LinkDevice(context.Background(), code, req)
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
	if resp != nil {
		t.Fatal("expected nil response on error")
	}
}

func TestLinkDevice_AccountNotFound(t *testing.T) {
	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	// Store a valid session pointing to a non-existent account.
	provStore.sessions["valid-code"] = &ProvisioningSession{
		Code:      "valid-code",
		UUID:      "nonexistent-uuid",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	req := validLinkDeviceRequest("valid-code")
	resp, err := mgr.LinkDevice(context.Background(), "valid-code", req)
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}
	if resp != nil {
		t.Fatal("expected nil response on error")
	}
}

func TestLinkDevice_SessionDeletedAfterSuccess(t *testing.T) {
	mgr, provStore, _, code := setupLinkDeviceTest(t)

	req := validLinkDeviceRequest(code)
	_, err := mgr.LinkDevice(context.Background(), code, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The provisioning session should be deleted after linking.
	if provStore.deleteCalled[code] < 1 {
		t.Fatal("expected delete to be called for consumed session")
	}
}

func TestLinkDevice_SessionDeleteFailureNonFatal(t *testing.T) {
	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	acctStore.accounts["test-uuid"] = &accounts.Account{
		UUID:        "test-uuid",
		Number:      "+15551234567",
		IdentityKey: []byte("identity-key"),
		Devices: []accounts.Device{
			{
				ID:        1,
				AuthToken: "primary-token",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte("pub"),
					Signature: []byte("sig"),
				},
			},
		},
	}

	code, err := mgr.CreateProvisioningCode(context.Background(), "test-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Set delete to fail after code is created.
	provStore.deleteErr = errors.New("delete failure")

	req := validLinkDeviceRequest(code.VerificationCode)
	resp, err := mgr.LinkDevice(context.Background(), code.VerificationCode, req)
	if err != nil {
		t.Fatalf("unexpected error: %v (delete failure should be non-fatal)", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestLinkDevice_PreKeyStoreFailureNonFatal(t *testing.T) {
	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keyStore := newMockPreKeyStore()
	keyStore.storeSignedErr = errors.New("pre-key store failure")
	keysMgr := keys.NewKeysManager(keyStore)
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	acctStore.accounts["test-uuid"] = &accounts.Account{
		UUID:        "test-uuid",
		Number:      "+15551234567",
		IdentityKey: []byte("identity-key"),
		Devices: []accounts.Device{
			{
				ID:        1,
				AuthToken: "primary-token",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte("pub"),
					Signature: []byte("sig"),
				},
			},
		},
	}

	code, err := mgr.CreateProvisioningCode(context.Background(), "test-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := validLinkDeviceRequest(code.VerificationCode)
	resp, err := mgr.LinkDevice(context.Background(), code.VerificationCode, req)
	// Pre-key storage failure is non-fatal per the code comment.
	if err != nil {
		t.Fatalf("unexpected error: %v (pre-key failure should be non-fatal)", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response even when pre-key store fails")
	}
}

// --- SetCapabilities tests ---

func TestSetCapabilities_Success(t *testing.T) {
	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	acctStore.accounts["test-uuid"] = &accounts.Account{
		UUID: "test-uuid",
		Devices: []accounts.Device{
			{
				ID:        1,
				AuthToken: "token",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte("pub"),
					Signature: []byte("sig"),
				},
			},
		},
	}

	caps := map[string]bool{
		"storage":                  true,
		"transfer":                 false,
		"paymentActivation":        true,
		"deleteSync":               false,
		"versionedExpirationTimer": true,
	}

	err := mgr.SetCapabilities(context.Background(), "test-uuid", 1, caps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify capabilities were set on the account.
	acct := acctStore.accounts["test-uuid"]
	device := acct.GetDevice(1)
	if device == nil {
		t.Fatal("expected device to exist")
		return
	}
	if !device.Capabilities.Storage {
		t.Fatal("expected Storage capability to be true")
	}
	if device.Capabilities.Transfer {
		t.Fatal("expected Transfer capability to be false")
	}
	if !device.Capabilities.PaymentActivation {
		t.Fatal("expected PaymentActivation capability to be true")
	}
	if !device.Capabilities.VersionedExpirationTimer {
		t.Fatal("expected VersionedExpirationTimer capability to be true")
	}
}

func TestSetCapabilities_EmptyCaps(t *testing.T) {
	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	acctStore.accounts["test-uuid"] = &accounts.Account{
		UUID: "test-uuid",
		Devices: []accounts.Device{
			{
				ID:        1,
				AuthToken: "token",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte("pub"),
					Signature: []byte("sig"),
				},
			},
		},
	}

	caps := map[string]bool{}
	err := mgr.SetCapabilities(context.Background(), "test-uuid", 1, caps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSetCapabilities_AccountNotFound(t *testing.T) {
	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	caps := map[string]bool{"storage": true}
	err := mgr.SetCapabilities(context.Background(), "nonexistent-uuid", 1, caps)
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}
}

func TestSetCapabilities_DeviceNotFound(t *testing.T) {
	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	acctStore.accounts["test-uuid"] = &accounts.Account{
		UUID: "test-uuid",
		Devices: []accounts.Device{
			{
				ID:        1,
				AuthToken: "token",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte("pub"),
					Signature: []byte("sig"),
				},
			},
		},
	}

	caps := map[string]bool{"storage": true}
	err := mgr.SetCapabilities(context.Background(), "test-uuid", 99, caps)
	if err == nil {
		t.Fatal("expected error for nonexistent device")
	}
}

func TestSetCapabilities_EmptyUUID(t *testing.T) {
	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	caps := map[string]bool{"storage": true}
	err := mgr.SetCapabilities(context.Background(), "", 1, caps)
	if err == nil {
		t.Fatal("expected error for empty UUID")
	}
}

// --- decodeSignedPreKey tests ---

func TestDecodeSignedPreKey_Success(t *testing.T) {
	pubBytes := []byte("test-public-key")
	sigBytes := []byte("test-signature")
	entity := &SignedPreKeyEntity{
		KeyId:     42,
		PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
		Signature: base64.StdEncoding.EncodeToString(sigBytes),
	}

	spk, err := decodeSignedPreKey(entity)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spk.KeyID != 42 {
		t.Fatalf("expected KeyID 42, got %d", spk.KeyID)
	}
	if string(spk.PublicKey) != string(pubBytes) {
		t.Fatalf("expected PublicKey %q, got %q", string(pubBytes), string(spk.PublicKey))
	}
	if string(spk.Signature) != string(sigBytes) {
		t.Fatalf("expected Signature %q, got %q", string(sigBytes), string(spk.Signature))
	}
}

func TestDecodeSignedPreKey_InvalidPublicKey(t *testing.T) {
	entity := &SignedPreKeyEntity{
		KeyId:     1,
		PublicKey: "!!!not-valid-base64!!!",
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
	}

	_, err := decodeSignedPreKey(entity)
	if err == nil {
		t.Fatal("expected error for invalid base64 public key")
	}
}

func TestDecodeSignedPreKey_InvalidSignature(t *testing.T) {
	entity := &SignedPreKeyEntity{
		KeyId:     1,
		PublicKey: base64.StdEncoding.EncodeToString([]byte("pub")),
		Signature: "!!!not-valid-base64!!!",
	}

	_, err := decodeSignedPreKey(entity)
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
}

// --- decodeSignedPreKeyForStore tests ---

func TestDecodeSignedPreKeyForStore_Success(t *testing.T) {
	pubBytes := []byte("store-public-key")
	sigBytes := []byte("store-signature")
	entity := &SignedPreKeyEntity{
		KeyId:     99,
		PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
		Signature: base64.StdEncoding.EncodeToString(sigBytes),
	}

	spk, err := decodeSignedPreKeyForStore(entity)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spk.KeyID != 99 {
		t.Fatalf("expected KeyID 99, got %d", spk.KeyID)
	}
	if string(spk.PublicKey) != string(pubBytes) {
		t.Fatalf("expected PublicKey %q, got %q", string(pubBytes), string(spk.PublicKey))
	}
	if string(spk.Signature) != string(sigBytes) {
		t.Fatalf("expected Signature %q, got %q", string(sigBytes), string(spk.Signature))
	}
}

func TestDecodeSignedPreKeyForStore_InvalidPublicKey(t *testing.T) {
	entity := &SignedPreKeyEntity{
		KeyId:     1,
		PublicKey: "!!!invalid!!!",
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
	}

	_, err := decodeSignedPreKeyForStore(entity)
	if err == nil {
		t.Fatal("expected error for invalid base64 public key")
	}
}

func TestDecodeSignedPreKeyForStore_InvalidSignature(t *testing.T) {
	entity := &SignedPreKeyEntity{
		KeyId:     1,
		PublicKey: base64.StdEncoding.EncodeToString([]byte("pub")),
		Signature: "!!!invalid!!!",
	}

	_, err := decodeSignedPreKeyForStore(entity)
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
}
