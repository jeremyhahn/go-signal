package service

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/devices"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// TestNewDeviceService_InterfaceSatisfaction verifies the concrete type
// satisfies the DeviceService interface at compile time.
func TestNewDeviceService_InterfaceSatisfaction(t *testing.T) {
	var _ DeviceService = (*deviceService)(nil)
}

// ─── ProvisioningStore mock ──────────────────────────────────────────────────

type mockProvisioningStore struct {
	mu       sync.Mutex
	sessions map[string]*devices.ProvisioningSession
	storeErr error
	getErr   error
}

func newMockProvisioningStore() *mockProvisioningStore {
	return &mockProvisioningStore{sessions: make(map[string]*devices.ProvisioningSession)}
}

func (s *mockProvisioningStore) StoreSession(_ context.Context, session *devices.ProvisioningSession) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *session
	s.sessions[session.Code] = &cp
	return nil
}

func (s *mockProvisioningStore) GetSession(_ context.Context, code string) (*devices.ProvisioningSession, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[code]
	if !ok {
		return nil, errors.New("session not found")
	}
	cp := *sess
	return &cp, nil
}

func (s *mockProvisioningStore) DeleteSession(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, code)
	return nil
}

// newTestDeviceService builds a DeviceService wired to in-memory stores.
func newTestDeviceService() (DeviceService, *accounts.AccountsManager, func(string) string) {
	accountStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(accountStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	provStore := newMockProvisioningStore()
	devMgr := devices.NewDevicesManager(provStore, acctMgr, keysMgr, slog.Default())
	svc := NewDeviceService(devMgr)

	// Helper: seed an account and return its UUID.
	seedAccount := func(number string) string {
		a := newTestAccount("dev-acct-"+number, number)
		_ = acctMgr.Create(context.Background(), a)
		return a.UUID
	}

	return svc, acctMgr, seedAccount
}

func TestDeviceService_CreateProvisioningCode_Success(t *testing.T) {
	svc, _, seed := newTestDeviceService()
	uuid := seed("+14155550020")

	code, err := svc.CreateProvisioningCode(context.Background(), uuid)
	if err != nil {
		t.Fatalf("CreateProvisioningCode: unexpected error: %v", err)
	}
	if code.VerificationCode == "" {
		t.Error("CreateProvisioningCode: expected non-empty verification code")
	}
}

func TestDeviceService_CreateProvisioningCode_StoreError(t *testing.T) {
	accountStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(accountStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	provStore := newMockProvisioningStore()
	provStore.storeErr = errors.New("provisioning store failure")
	devMgr := devices.NewDevicesManager(provStore, acctMgr, keysMgr, slog.Default())
	svc := NewDeviceService(devMgr)

	_, err := svc.CreateProvisioningCode(context.Background(), "some-uuid")
	if err == nil {
		t.Fatal("CreateProvisioningCode: expected error from store")
	}
}

func TestDeviceService_LinkDevice_Success(t *testing.T) {
	svc, _, seed := newTestDeviceService()
	uuid := seed("+14155550021")

	// First get a provisioning code.
	code, err := svc.CreateProvisioningCode(context.Background(), uuid)
	if err != nil {
		t.Fatalf("CreateProvisioningCode: %v", err)
	}

	req := &devices.LinkDeviceRequest{
		VerificationCode: code.VerificationCode,
		AccountAttributes: devices.DeviceAccountAttributes{
			FetchesMessages: true,
			RegistrationId:  42,
			Name:            "Test Device",
		},
		AciSignedPreKey: devices.SignedPreKeyEntity{
			KeyId:     1,
			PublicKey: "dGVzdHB1YmxpY2tleQ==", // base64("testpublickey")
			Signature: "dGVzdHNpZ25hdHVyZQ==", // base64("testsignature")
		},
	}

	resp, err := svc.LinkDevice(context.Background(), code.VerificationCode, req)
	if err != nil {
		t.Fatalf("LinkDevice: unexpected error: %v", err)
	}
	if resp.DeviceId == 0 {
		t.Error("LinkDevice: expected non-zero DeviceId")
	}
}

func TestDeviceService_LinkDevice_InvalidCode(t *testing.T) {
	svc, _, _ := newTestDeviceService()

	req := &devices.LinkDeviceRequest{VerificationCode: "bad-code"}
	_, err := svc.LinkDevice(context.Background(), "bad-code", req)
	if err == nil {
		t.Fatal("LinkDevice: expected error for invalid provisioning code")
	}
}

func TestDeviceService_LinkDevice_ExpiredCode(t *testing.T) {
	accountStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(accountStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	provStore := newMockProvisioningStore()
	devMgr := devices.NewDevicesManager(provStore, acctMgr, keysMgr, slog.Default())
	svc := NewDeviceService(devMgr)

	// Directly insert an already-expired session.
	expired := &devices.ProvisioningSession{
		Code:      "expired-code",
		UUID:      "some-uuid",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	_ = provStore.StoreSession(context.Background(), expired)

	req := &devices.LinkDeviceRequest{VerificationCode: "expired-code"}
	_, err := svc.LinkDevice(context.Background(), "expired-code", req)
	if err == nil {
		t.Fatal("LinkDevice: expected error for expired provisioning code")
	}
}

func TestDeviceService_SetCapabilities_Success(t *testing.T) {
	svc, acctMgr, seed := newTestDeviceService()
	uuid := seed("+14155550022")

	// Prime account in acctMgr store by creating via the manager.
	a := newTestAccount(uuid, "+14155550022")
	_ = acctMgr.Create(context.Background(), a)

	caps := map[string]bool{
		"storage":  true,
		"transfer": false,
	}
	err := svc.SetCapabilities(context.Background(), uuid, accounts.PrimaryDeviceID, caps)
	if err != nil {
		t.Fatalf("SetCapabilities: unexpected error: %v", err)
	}
}

func TestDeviceService_SetCapabilities_UnknownAccount(t *testing.T) {
	svc, _, _ := newTestDeviceService()

	err := svc.SetCapabilities(context.Background(), "unknown-uuid", 1, map[string]bool{})
	if err == nil {
		t.Fatal("SetCapabilities: expected error for unknown account")
	}
}

func TestDeviceService_LinkDeviceForAccount_Success(t *testing.T) {
	svc, _, seed := newTestDeviceService()
	uuid := seed("+14155550030")

	// Obtain a provisioning code for this account.
	code, err := svc.CreateProvisioningCode(context.Background(), uuid)
	if err != nil {
		t.Fatalf("CreateProvisioningCode: %v", err)
	}

	req := &devices.LinkDeviceRequest{
		VerificationCode: code.VerificationCode,
		AccountAttributes: devices.DeviceAccountAttributes{
			FetchesMessages: true,
			RegistrationId:  99,
			Name:            "Linked Device",
		},
		AciSignedPreKey: devices.SignedPreKeyEntity{
			KeyId:     1,
			PublicKey: "dGVzdHB1YmxpY2tleQ==",
			Signature: "dGVzdHNpZ25hdHVyZQ==",
		},
	}

	resp, err := svc.LinkDeviceForAccount(context.Background(), uuid, code.VerificationCode, req)
	if err != nil {
		t.Fatalf("LinkDeviceForAccount: unexpected error: %v", err)
	}
	if resp.DeviceId == 0 {
		t.Error("LinkDeviceForAccount: expected non-zero DeviceId")
	}
}

func TestDeviceService_LinkDeviceForAccount_WrongAccount(t *testing.T) {
	svc, _, seed := newTestDeviceService()
	seed("+14155550031")
	uuid2 := seed("+14155550032")

	// Create provisioning code for uuid2.
	code, err := svc.CreateProvisioningCode(context.Background(), uuid2)
	if err != nil {
		t.Fatalf("CreateProvisioningCode: %v", err)
	}

	req := &devices.LinkDeviceRequest{
		VerificationCode: code.VerificationCode,
	}

	// Attempt to link using uuid1 (wrong owner) — must fail.
	_, err = svc.LinkDeviceForAccount(context.Background(), "different-uuid", code.VerificationCode, req)
	if err == nil {
		t.Fatal("LinkDeviceForAccount: expected error when code belongs to a different account")
	}
}
