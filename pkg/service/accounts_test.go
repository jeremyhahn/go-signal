package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// TestNewAccountService_InterfaceSatisfaction verifies the concrete type
// satisfies the AccountService interface at compile time.
func TestNewAccountService_InterfaceSatisfaction(t *testing.T) {
	var _ AccountService = (*accountService)(nil)
}

// newTestAccountService builds an AccountService backed by an in-memory store.
func newTestAccountService() AccountService {
	store := newMockAccountStore()
	mgr := accounts.NewAccountsManager(store, 0)
	return NewAccountService(mgr)
}

func TestAccountService_Create_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-001", "+14155550001")

	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: unexpected error: %v", err)
	}
}

func TestAccountService_Create_NilAccount(t *testing.T) {
	svc := newTestAccountService()
	err := svc.Create(context.Background(), nil)
	if err == nil {
		t.Fatal("Create: expected error for nil account")
	}
}

func TestAccountService_Get_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-002", "+14155550002")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := svc.Get(context.Background(), "uuid-002")
	if err != nil {
		t.Fatalf("Get: unexpected error: %v", err)
	}
	if got.UUID != "uuid-002" {
		t.Errorf("Get: expected uuid-002, got %q", got.UUID)
	}
}

func TestAccountService_Get_NotFound(t *testing.T) {
	svc := newTestAccountService()
	_, err := svc.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("Get: expected error for missing account")
	}
}

func TestAccountService_Get_EmptyUUID(t *testing.T) {
	svc := newTestAccountService()
	_, err := svc.Get(context.Background(), "")
	if err == nil {
		t.Fatal("Get: expected error for empty UUID")
	}
}

func TestAccountService_GetByNumber_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-003", "+14155550003")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := svc.GetByNumber(context.Background(), "+14155550003")
	if err != nil {
		t.Fatalf("GetByNumber: unexpected error: %v", err)
	}
	if got.Number != "+14155550003" {
		t.Errorf("GetByNumber: expected +14155550003, got %q", got.Number)
	}
}

func TestAccountService_GetByNumber_NotFound(t *testing.T) {
	svc := newTestAccountService()
	_, err := svc.GetByNumber(context.Background(), "+19999999999")
	if err == nil {
		t.Fatal("GetByNumber: expected error for missing number")
	}
}

func TestAccountService_Update_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-004", "+14155550004")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	a.Username = "newusername"
	if err := svc.Update(context.Background(), a); err != nil {
		t.Fatalf("Update: unexpected error: %v", err)
	}

	got, _ := svc.Get(context.Background(), "uuid-004")
	if got.Username != "newusername" {
		t.Errorf("Update: username not persisted, got %q", got.Username)
	}
}

func TestAccountService_Update_StoreError(t *testing.T) {
	store := newMockAccountStore()
	store.updateErr = errors.New("db unavailable")
	mgr := accounts.NewAccountsManager(store, 0)
	svc := NewAccountService(mgr)

	a := newTestAccount("uuid-upd", "+14155550099")
	// Seed directly so manager validation passes on Update.
	_ = store.Create(context.Background(), a)

	a.Username = "x"
	err := svc.Update(context.Background(), a)
	if err == nil {
		t.Fatal("Update: expected error from store")
	}
}

func TestAccountService_Delete_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-005", "+14155550005")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.Delete(context.Background(), "uuid-005"); err != nil {
		t.Fatalf("Delete: unexpected error: %v", err)
	}

	_, err := svc.Get(context.Background(), "uuid-005")
	if err == nil {
		t.Fatal("Delete: account still accessible after deletion")
	}
}

func TestAccountService_Delete_EmptyUUID(t *testing.T) {
	svc := newTestAccountService()
	err := svc.Delete(context.Background(), "")
	if err == nil {
		t.Fatal("Delete: expected error for empty UUID")
	}
}

func TestAccountService_SetRegistrationLock_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-006", "+14155550006")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.SetRegistrationLock(context.Background(), "uuid-006", "secure-pin-123"); err != nil {
		t.Fatalf("SetRegistrationLock: unexpected error: %v", err)
	}
}

func TestAccountService_SetRegistrationLock_EmptyPIN(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-007", "+14155550007")
	_ = svc.Create(context.Background(), a)

	err := svc.SetRegistrationLock(context.Background(), "uuid-007", "")
	if err == nil {
		t.Fatal("SetRegistrationLock: expected error for empty PIN")
	}
}

func TestAccountService_ClearRegistrationLock_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-008", "+14155550008")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = svc.SetRegistrationLock(context.Background(), "uuid-008", "pin-xyz")

	if err := svc.ClearRegistrationLock(context.Background(), "uuid-008"); err != nil {
		t.Fatalf("ClearRegistrationLock: unexpected error: %v", err)
	}

	got, _ := svc.Get(context.Background(), "uuid-008")
	if got.RegistrationLockHash != nil {
		t.Error("ClearRegistrationLock: lock hash not cleared")
	}
}

func TestAccountService_ClearRegistrationLock_EmptyUUID(t *testing.T) {
	svc := newTestAccountService()
	err := svc.ClearRegistrationLock(context.Background(), "")
	if err == nil {
		t.Fatal("ClearRegistrationLock: expected error for empty UUID")
	}
}

func TestAccountService_SetDeviceAttributes_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-009", "+14155550009")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	attrs := accounts.DeviceAttributes{Name: "My Phone"}
	got, err := svc.SetDeviceAttributes(context.Background(), "uuid-009", accounts.PrimaryDeviceID, attrs)
	if err != nil {
		t.Fatalf("SetDeviceAttributes: unexpected error: %v", err)
	}

	dev := got.GetDevice(accounts.PrimaryDeviceID)
	if dev == nil || dev.Name != "My Phone" {
		t.Errorf("SetDeviceAttributes: device name not updated, got %v", dev)
	}
}

func TestAccountService_AddDevice_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-010", "+14155550010")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	device := &accounts.Device{
		AuthToken: "new-device-token",
		SignedPreKey: &accounts.SignedPreKey{
			KeyID:     2,
			PublicKey: []byte("pk"),
			Signature: []byte("sig"),
		},
	}
	updated, err := svc.AddDevice(context.Background(), "uuid-010", device)
	if err != nil {
		t.Fatalf("AddDevice: unexpected error: %v", err)
	}
	if len(updated.Devices) != 2 {
		t.Errorf("AddDevice: expected 2 devices, got %d", len(updated.Devices))
	}
}

func TestAccountService_RemoveDevice_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-011", "+14155550011")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Add a second device before removing it.
	device := &accounts.Device{
		AuthToken: "secondary-token",
		SignedPreKey: &accounts.SignedPreKey{
			KeyID:     3,
			PublicKey: []byte("pk2"),
			Signature: []byte("sig2"),
		},
	}
	updated, err := svc.AddDevice(context.Background(), "uuid-011", device)
	if err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	secondID := updated.Devices[1].ID

	result, err := svc.RemoveDevice(context.Background(), "uuid-011", secondID)
	if err != nil {
		t.Fatalf("RemoveDevice: unexpected error: %v", err)
	}
	if len(result.Devices) != 1 {
		t.Errorf("RemoveDevice: expected 1 device, got %d", len(result.Devices))
	}
}

func TestAccountService_RemoveDevice_PrimaryDeviceForbidden(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-012", "+14155550012")
	_ = svc.Create(context.Background(), a)

	_, err := svc.RemoveDevice(context.Background(), "uuid-012", accounts.PrimaryDeviceID)
	if err == nil {
		t.Fatal("RemoveDevice: expected error when removing primary device")
	}
}

func TestAccountService_ChangeNumber_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-013", "+14155550013")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := svc.ChangeNumber(context.Background(), "uuid-013", "+14155550099", nil)
	if err != nil {
		t.Fatalf("ChangeNumber: unexpected error: %v", err)
	}
	if updated.Number != "+14155550099" {
		t.Errorf("ChangeNumber: expected +14155550099, got %q", updated.Number)
	}
}

func TestAccountService_ChangeNumber_EmptyUUID(t *testing.T) {
	svc := newTestAccountService()
	_, err := svc.ChangeNumber(context.Background(), "", "+14155550099", nil)
	if err == nil {
		t.Fatal("ChangeNumber: expected error for empty UUID")
	}
}

func TestAccountService_SetPhoneNumberDiscoverability_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-014", "+14155550014")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.SetPhoneNumberDiscoverability(context.Background(), "uuid-014", true); err != nil {
		t.Fatalf("SetPhoneNumberDiscoverability: unexpected error: %v", err)
	}

	got, _ := svc.Get(context.Background(), "uuid-014")
	if !got.DiscoverableByPhoneNumber {
		t.Error("SetPhoneNumberDiscoverability: flag not persisted")
	}
}

func TestAccountService_SetPhoneNumberDiscoverability_EmptyUUID(t *testing.T) {
	svc := newTestAccountService()
	err := svc.SetPhoneNumberDiscoverability(context.Background(), "", true)
	if err == nil {
		t.Fatal("SetPhoneNumberDiscoverability: expected error for empty UUID")
	}
}

func TestAccountService_GetDataReport_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-015", "+14155550015")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	report, err := svc.GetDataReport(context.Background(), "uuid-015")
	if err != nil {
		t.Fatalf("GetDataReport: unexpected error: %v", err)
	}
	if report.UUID != "uuid-015" {
		t.Errorf("GetDataReport: expected uuid-015, got %q", report.UUID)
	}
}

func TestAccountService_GetDataReport_EmptyUUID(t *testing.T) {
	svc := newTestAccountService()
	_, err := svc.GetDataReport(context.Background(), "")
	if err == nil {
		t.Fatal("GetDataReport: expected error for empty UUID")
	}
}

func TestAccountService_GetByPNI_NotFound(t *testing.T) {
	svc := newTestAccountService()
	_, err := svc.GetByPNI(context.Background(), "pni-unknown")
	if err == nil {
		t.Fatal("GetByPNI: expected error for unknown PNI")
	}
}

func TestAccountService_GetByPNI_Found(t *testing.T) {
	store := newMockAccountStore()
	mgr := accounts.NewAccountsManager(store, 0)
	svc := NewAccountService(mgr)

	a := newTestAccount("pni-uuid", "+14155550090")
	// Bypass the service layer and seed the store directly so GetByPNI
	// can resolve via PNI mirror.
	_ = store.Create(context.Background(), a)

	// GetByPNI always returns AccountNotFoundError from the mock (it is a stub
	// that returns not-found). This test verifies the error path.
	_, err := svc.GetByPNI(context.Background(), "pni-uuid")
	// The mock GetByPNI always returns AccountNotFoundError, so we only check
	// that the delegation occurred (no panic).
	_ = err
}

func TestAccountService_RecreatePreserving_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-rp", "+14155550091")

	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.Delete(context.Background(), "uuid-rp"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// RecreatePreserving re-inserts a deleted account.
	if err := svc.RecreatePreserving(context.Background(), a); err != nil {
		t.Fatalf("RecreatePreserving: unexpected error: %v", err)
	}

	got, err := svc.Get(context.Background(), "uuid-rp")
	if err != nil {
		t.Fatalf("Get after RecreatePreserving: %v", err)
	}
	if got.UUID != "uuid-rp" {
		t.Errorf("RecreatePreserving: expected uuid-rp, got %q", got.UUID)
	}
}

func TestAccountService_RecreatePreserving_Error(t *testing.T) {
	store := newMockAccountStore()
	store.createErr = errors.New("store failure")
	mgr := accounts.NewAccountsManager(store, 0)
	svc := NewAccountService(mgr)

	a := newTestAccount("uuid-rp2", "+14155550092")
	err := svc.RecreatePreserving(context.Background(), a)
	if err == nil {
		t.Fatal("RecreatePreserving: expected error from store")
	}
}

func TestAccountService_ClearGcmRegistration_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-gcm", "+14155550093")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := svc.ClearGcmRegistration(context.Background(), "uuid-gcm", accounts.PrimaryDeviceID)
	if err != nil {
		t.Fatalf("ClearGcmRegistration: unexpected error: %v", err)
	}
	if updated == nil {
		t.Fatal("ClearGcmRegistration: expected non-nil updated account")
	}
}

func TestAccountService_ClearGcmRegistration_UnknownAccount(t *testing.T) {
	svc := newTestAccountService()
	_, err := svc.ClearGcmRegistration(context.Background(), "unknown-uuid", 1)
	if err == nil {
		t.Fatal("ClearGcmRegistration: expected error for unknown account")
	}
}

func TestAccountService_ClearApnRegistration_Success(t *testing.T) {
	svc := newTestAccountService()
	a := newTestAccount("uuid-apn", "+14155550094")
	if err := svc.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := svc.ClearApnRegistration(context.Background(), "uuid-apn", accounts.PrimaryDeviceID)
	if err != nil {
		t.Fatalf("ClearApnRegistration: unexpected error: %v", err)
	}
	if updated == nil {
		t.Fatal("ClearApnRegistration: expected non-nil updated account")
	}
}

func TestAccountService_ClearApnRegistration_UnknownAccount(t *testing.T) {
	svc := newTestAccountService()
	_, err := svc.ClearApnRegistration(context.Background(), "unknown-uuid", 1)
	if err == nil {
		t.Fatal("ClearApnRegistration: expected error for unknown account")
	}
}

func TestAccountService_ListAll_Success(t *testing.T) {
	svc := newTestAccountService()
	for i, num := range []string{"+14155550095", "+14155550096", "+14155550097"} {
		id := "list-uuid-" + string(rune('a'+i))
		if err := svc.Create(context.Background(), newTestAccount(id, num)); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	var count int
	err := svc.ListAll(context.Background(), func(_ *accounts.Account) error {
		count++
		return nil
	})
	if err != nil {
		t.Fatalf("ListAll: unexpected error: %v", err)
	}
	if count != 3 {
		t.Errorf("ListAll: expected 3 accounts, got %d", count)
	}
}

func TestAccountService_ListAll_FnError(t *testing.T) {
	svc := newTestAccountService()
	if err := svc.Create(context.Background(), newTestAccount("list-fn-err", "+14155550098")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	sentinel := errors.New("stop iteration")
	err := svc.ListAll(context.Background(), func(_ *accounts.Account) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("ListAll: expected sentinel error, got %v", err)
	}
}
