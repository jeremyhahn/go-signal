package accounts

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// memoryStore is an in-memory AccountStore for testing.
type memoryStore struct {
	mu        sync.RWMutex
	accounts  map[string]*Account
	byNumber  map[string]string // number -> uuid
	byPNI     map[string]string // PNI -> uuid
	createErr error
	updateErr error
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		accounts: make(map[string]*Account),
		byNumber: make(map[string]string),
		byPNI:    make(map[string]string),
	}
}

func (s *memoryStore) Create(_ context.Context, account *Account) error {
	if s.createErr != nil {
		return s.createErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.accounts[account.UUID]; ok {
		return &AccountAlreadyExistsError{Identifier: account.UUID}
	}
	if _, ok := s.byNumber[account.Number]; ok {
		return &AccountAlreadyExistsError{Identifier: account.Number}
	}

	cp := copyAccount(account)
	s.accounts[account.UUID] = cp
	s.byNumber[account.Number] = account.UUID
	if account.PNI != "" {
		s.byPNI[account.PNI] = account.UUID
	}
	return nil
}

func (s *memoryStore) Get(_ context.Context, uuid string) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	a, ok := s.accounts[uuid]
	if !ok {
		return nil, &AccountNotFoundError{Identifier: uuid}
	}
	return copyAccount(a), nil
}

func (s *memoryStore) GetByNumber(_ context.Context, number string) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uuid, ok := s.byNumber[number]
	if !ok {
		return nil, &AccountNotFoundError{Identifier: number}
	}
	return copyAccount(s.accounts[uuid]), nil
}

// GetByPNI is a minimal implementation for the manager_test memory
// store. Tests that care about PNI lookup can populate byPNI directly.
func (s *memoryStore) GetByPNI(_ context.Context, pni string) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uuid, ok := s.byPNI[pni]
	if !ok {
		return nil, &AccountNotFoundError{Identifier: pni}
	}
	return copyAccount(s.accounts[uuid]), nil
}

func (s *memoryStore) Update(_ context.Context, account *Account) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.accounts[account.UUID]; !ok {
		return &AccountNotFoundError{Identifier: account.UUID}
	}
	s.accounts[account.UUID] = copyAccount(account)
	return nil
}

func (s *memoryStore) Delete(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.accounts[uuid]
	if !ok {
		return &AccountNotFoundError{Identifier: uuid}
	}
	delete(s.byNumber, a.Number)
	delete(s.accounts, uuid)
	return nil
}

func (s *memoryStore) ListAll(_ context.Context, fn func(*Account) error) error {
	s.mu.Lock()
	snap := make([]*Account, 0, len(s.accounts))
	for _, a := range s.accounts {
		snap = append(snap, copyAccount(a))
	}
	s.mu.Unlock()
	for _, a := range snap {
		if err := fn(a); err != nil {
			return err
		}
	}
	return nil
}

func copyAccount(a *Account) *Account {
	cp := *a
	cp.Devices = make([]Device, len(a.Devices))
	copy(cp.Devices, a.Devices)
	cp.IdentityKey = append([]byte(nil), a.IdentityKey...)
	return &cp
}

// validDevice returns a Device that passes validateDevice.
func validDevice() Device {
	return Device{
		ID:        PrimaryDeviceID,
		AuthToken: "auth-token-1",
		SignedPreKey: &SignedPreKey{
			KeyID:     1,
			PublicKey: []byte("pub-key"),
			Signature: []byte("signature"),
		},
	}
}

// validAccount returns an Account that passes validateAccountForCreation.
func validAccount() *Account {
	return &Account{
		UUID:        "test-uuid-1",
		Number:      "+15551234567",
		IdentityKey: []byte("identity-key"),
		Devices:     []Device{validDevice()},
	}
}

// --- NewAccountsManager ---

func TestNewAccountsManager_DefaultMaxDevices(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	if m.maxDevices != DefaultMaxDevices {
		t.Errorf("maxDevices = %d, want %d", m.maxDevices, DefaultMaxDevices)
	}
}

func TestNewAccountsManager_NegativeMaxDevices(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), -1)
	if m.maxDevices != DefaultMaxDevices {
		t.Errorf("maxDevices = %d, want %d", m.maxDevices, DefaultMaxDevices)
	}
}

func TestNewAccountsManager_CustomMaxDevices(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 10)
	if m.maxDevices != 10 {
		t.Errorf("maxDevices = %d, want 10", m.maxDevices)
	}
}

func TestNewAccountsManager_StoresStore(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	if m.store != store {
		t.Error("store was not set correctly")
	}
}

// --- Create ---

func TestCreate_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if acct.Version != 1 {
		t.Errorf("Version = %d, want 1", acct.Version)
	}
	if acct.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if acct.Devices[0].CreatedAt.IsZero() {
		t.Error("Device.CreatedAt should be set")
	}
	if acct.Devices[0].LastSeen.IsZero() {
		t.Error("Device.LastSeen should be set")
	}

	// Verify it was persisted.
	retrieved, err := store.Get(ctx, acct.UUID)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if retrieved.UUID != acct.UUID {
		t.Errorf("retrieved UUID = %q, want %q", retrieved.UUID, acct.UUID)
	}
}

func TestCreate_NilAccount(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.Create(context.Background(), nil)
	if err == nil {
		t.Fatal("Create(nil) should return error")
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Errorf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestCreate_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.UUID = ""
	err := m.Create(context.Background(), acct)
	assertInvalidArgErr(t, err, "uuid")
}

func TestCreate_EmptyNumber(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.Number = ""
	err := m.Create(context.Background(), acct)
	assertInvalidArgErr(t, err, "number")
}

func TestCreate_EmptyIdentityKey(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.IdentityKey = nil
	err := m.Create(context.Background(), acct)
	assertInvalidArgErr(t, err, "identityKey")
}

func TestCreate_NoDevices(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.Devices = nil
	err := m.Create(context.Background(), acct)
	assertInvalidArgErr(t, err, "devices")
}

func TestCreate_NoPrimaryDevice(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.Devices[0].ID = 2 // not primary
	err := m.Create(context.Background(), acct)
	assertInvalidArgErr(t, err, "devices")
}

func TestCreate_DeviceMissingAuthToken(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.Devices[0].AuthToken = ""
	err := m.Create(context.Background(), acct)
	assertInvalidArgErr(t, err, "device.authToken")
}

func TestCreate_DeviceMissingSignedPreKey(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.Devices[0].SignedPreKey = nil
	err := m.Create(context.Background(), acct)
	assertInvalidArgErr(t, err, "device.signedPreKey")
}

func TestCreate_DeviceSignedPreKeyEmptyPublicKey(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.Devices[0].SignedPreKey.PublicKey = nil
	err := m.Create(context.Background(), acct)
	assertInvalidArgErr(t, err, "device.signedPreKey.publicKey")
}

func TestCreate_DeviceSignedPreKeyEmptySignature(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.Devices[0].SignedPreKey.Signature = nil
	err := m.Create(context.Background(), acct)
	assertInvalidArgErr(t, err, "device.signedPreKey.signature")
}

func TestCreate_DuplicateAccount(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("first Create() error = %v", err)
	}

	acct2 := validAccount()
	err := m.Create(ctx, acct2)
	if err == nil {
		t.Fatal("duplicate Create() should return error")
	}
	var target *AccountAlreadyExistsError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountAlreadyExistsError, got %T: %v", err, err)
	}
}

func TestCreate_StoreError(t *testing.T) {
	store := newMemoryStore()
	store.createErr = &AccountAlreadyExistsError{Identifier: "forced"}
	m := NewAccountsManager(store, 0)

	err := m.Create(context.Background(), validAccount())
	if err == nil {
		t.Fatal("expected store error to propagate")
	}
}

func TestCreate_MultipleDevicesTimestamps(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	acct := validAccount()
	secondDevice := validDevice()
	secondDevice.ID = 2
	acct.Devices = append(acct.Devices, secondDevice)

	if err := m.Create(context.Background(), acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	for i, d := range acct.Devices {
		if d.CreatedAt.IsZero() {
			t.Errorf("Devices[%d].CreatedAt should be set", i)
		}
		if d.LastSeen.IsZero() {
			t.Errorf("Devices[%d].LastSeen should be set", i)
		}
	}
}

// --- Get ---

func TestGet_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, err := m.Get(ctx, acct.UUID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.UUID != acct.UUID {
		t.Errorf("UUID = %q, want %q", got.UUID, acct.UUID)
	}
}

func TestGet_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.Get(context.Background(), "")
	assertInvalidArgErr(t, err, "uuid")
}

func TestGet_NotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

// --- GetByNumber ---

func TestGetByNumber_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, err := m.GetByNumber(ctx, acct.Number)
	if err != nil {
		t.Fatalf("GetByNumber() error = %v", err)
	}
	if got.Number != acct.Number {
		t.Errorf("Number = %q, want %q", got.Number, acct.Number)
	}
}

func TestGetByNumber_EmptyNumber(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.GetByNumber(context.Background(), "")
	assertInvalidArgErr(t, err, "number")
}

func TestGetByNumber_NotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.GetByNumber(context.Background(), "+10000000000")
	if err == nil {
		t.Fatal("expected error for nonexistent number")
	}
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

// --- Update ---

func TestUpdate_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, _ := m.Get(ctx, acct.UUID)
	got.Username = "alice"
	prevVersion := got.Version

	if err := m.Update(ctx, got); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if got.Version != prevVersion+1 {
		t.Errorf("Version = %d, want %d", got.Version, prevVersion+1)
	}

	updated, _ := m.Get(ctx, acct.UUID)
	if updated.Username != "alice" {
		t.Errorf("Username = %q, want %q", updated.Username, "alice")
	}
}

func TestUpdate_NilAccount(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.Update(context.Background(), nil)
	assertInvalidArgErr(t, err, "account")
}

func TestUpdate_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.Update(context.Background(), &Account{})
	assertInvalidArgErr(t, err, "uuid")
}

func TestUpdate_NotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.Update(context.Background(), &Account{UUID: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestUpdate_VersionIncrement(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	got, _ := m.Get(ctx, acct.UUID)
	if got.Version != 1 {
		t.Fatalf("initial Version = %d, want 1", got.Version)
	}

	if err := m.Update(ctx, got); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if got.Version != 2 {
		t.Errorf("after update Version = %d, want 2", got.Version)
	}
}

func TestUpdate_StoreError(t *testing.T) {
	store := newMemoryStore()
	store.updateErr = &VersionConflictError{AccountUUID: "u", ExpectedVersion: 1, ActualVersion: 2}
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	// Seed the store directly so Create works.
	store.accounts[acct.UUID] = copyAccount(acct)
	store.byNumber[acct.Number] = acct.UUID

	err := m.Update(ctx, &Account{UUID: acct.UUID})
	if err == nil {
		t.Fatal("expected store error to propagate")
	}
	var target *VersionConflictError
	if !errors.As(err, &target) {
		t.Errorf("expected VersionConflictError, got %T: %v", err, err)
	}
}

// --- Delete ---

func TestDelete_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := m.Delete(ctx, acct.UUID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err := m.Get(ctx, acct.UUID)
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError after delete, got %T: %v", err, err)
	}
}

func TestDelete_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.Delete(context.Background(), "")
	assertInvalidArgErr(t, err, "uuid")
}

func TestDelete_NotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.Delete(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

// --- AddDevice ---

func TestAddDevice_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	newDev := &Device{
		AuthToken: "new-token",
		SignedPreKey: &SignedPreKey{
			KeyID:     2,
			PublicKey: []byte("pub2"),
			Signature: []byte("sig2"),
		},
	}
	result, err := m.AddDevice(ctx, acct.UUID, newDev)
	if err != nil {
		t.Fatalf("AddDevice() error = %v", err)
	}

	if len(result.Devices) != 2 {
		t.Fatalf("Devices count = %d, want 2", len(result.Devices))
	}

	added := result.GetDevice(2)
	if added == nil {
		t.Fatal("expected device with ID 2")
		return
	}
	if added.AuthToken != "new-token" {
		t.Errorf("AuthToken = %q, want %q", added.AuthToken, "new-token")
	}
	if added.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if added.LastSeen.IsZero() {
		t.Error("LastSeen should be set")
	}
}

func TestAddDevice_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.AddDevice(context.Background(), "", &Device{})
	assertInvalidArgErr(t, err, "uuid")
}

func TestAddDevice_NilDevice(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.AddDevice(context.Background(), "uuid", nil)
	assertInvalidArgErr(t, err, "device")
}

func TestAddDevice_InvalidDevice(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Device missing auth token
	_, err := m.AddDevice(ctx, acct.UUID, &Device{
		SignedPreKey: &SignedPreKey{PublicKey: []byte("k"), Signature: []byte("s")},
	})
	assertInvalidArgErr(t, err, "device.authToken")
}

func TestAddDevice_AccountNotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	dev := &Device{
		AuthToken:    "tok",
		SignedPreKey: &SignedPreKey{PublicKey: []byte("k"), Signature: []byte("s")},
	}
	_, err := m.AddDevice(context.Background(), "nonexistent", dev)
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestAddDevice_DeviceLimitExceeded(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 2) // max 2 devices
	ctx := context.Background()

	acct := validAccount()
	secondDev := validDevice()
	secondDev.ID = 2
	acct.Devices = append(acct.Devices, secondDev)
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	newDev := &Device{
		AuthToken:    "tok3",
		SignedPreKey: &SignedPreKey{PublicKey: []byte("k"), Signature: []byte("s")},
	}
	_, err := m.AddDevice(ctx, acct.UUID, newDev)
	if err == nil {
		t.Fatal("expected DeviceLimitExceededError")
	}
	var target *DeviceLimitExceededError
	if !errors.As(err, &target) {
		t.Errorf("expected DeviceLimitExceededError, got %T: %v", err, err)
	}
	if target.MaxDevices != 2 {
		t.Errorf("MaxDevices = %d, want 2", target.MaxDevices)
	}
}

func TestAddDevice_AssignsNextID(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 10)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	newDev := func() *Device {
		return &Device{
			AuthToken:    "tok",
			SignedPreKey: &SignedPreKey{PublicKey: []byte("k"), Signature: []byte("s")},
		}
	}

	// Add device 2
	result, err := m.AddDevice(ctx, acct.UUID, newDev())
	if err != nil {
		t.Fatalf("AddDevice() error = %v", err)
	}
	if result.Devices[1].ID != 2 {
		t.Errorf("second device ID = %d, want 2", result.Devices[1].ID)
	}

	// Add device 3
	result, err = m.AddDevice(ctx, acct.UUID, newDev())
	if err != nil {
		t.Fatalf("AddDevice() error = %v", err)
	}
	if result.Devices[2].ID != 3 {
		t.Errorf("third device ID = %d, want 3", result.Devices[2].ID)
	}
}

func TestAddDevice_VersionIncrement(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	dev := &Device{
		AuthToken:    "tok",
		SignedPreKey: &SignedPreKey{PublicKey: []byte("k"), Signature: []byte("s")},
	}
	result, err := m.AddDevice(ctx, acct.UUID, dev)
	if err != nil {
		t.Fatalf("AddDevice() error = %v", err)
	}
	if result.Version != 2 {
		t.Errorf("Version = %d, want 2", result.Version)
	}
}

func TestAddDevice_StoreUpdateError(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Set update error after account is created.
	store.updateErr = &VersionConflictError{AccountUUID: acct.UUID}

	dev := &Device{
		AuthToken:    "tok",
		SignedPreKey: &SignedPreKey{PublicKey: []byte("k"), Signature: []byte("s")},
	}
	_, err := m.AddDevice(ctx, acct.UUID, dev)
	if err == nil {
		t.Fatal("expected error from store.Update")
	}
}

// --- RemoveDevice ---

func TestRemoveDevice_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	secondDev := validDevice()
	secondDev.ID = 2
	acct.Devices = append(acct.Devices, secondDev)
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	result, err := m.RemoveDevice(ctx, acct.UUID, 2)
	if err != nil {
		t.Fatalf("RemoveDevice() error = %v", err)
	}
	if len(result.Devices) != 1 {
		t.Errorf("Devices count = %d, want 1", len(result.Devices))
	}
	if result.GetDevice(2) != nil {
		t.Error("device 2 should have been removed")
	}
}

func TestRemoveDevice_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.RemoveDevice(context.Background(), "", 2)
	assertInvalidArgErr(t, err, "uuid")
}

func TestRemoveDevice_PrimaryDevice(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.RemoveDevice(context.Background(), "uuid-1", PrimaryDeviceID)
	if err == nil {
		t.Fatal("expected PrimaryDeviceRemovalError")
	}
	var target *PrimaryDeviceRemovalError
	if !errors.As(err, &target) {
		t.Errorf("expected PrimaryDeviceRemovalError, got %T: %v", err, err)
	}
}

func TestRemoveDevice_AccountNotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.RemoveDevice(context.Background(), "nonexistent", 2)
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestRemoveDevice_DeviceNotFound(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	_, err := m.RemoveDevice(ctx, acct.UUID, 99)
	if err == nil {
		t.Fatal("expected DeviceNotFoundError")
	}
	var target *DeviceNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected DeviceNotFoundError, got %T: %v", err, err)
	}
}

func TestRemoveDevice_VersionIncrement(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	secondDev := validDevice()
	secondDev.ID = 2
	acct.Devices = append(acct.Devices, secondDev)
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	result, err := m.RemoveDevice(ctx, acct.UUID, 2)
	if err != nil {
		t.Fatalf("RemoveDevice() error = %v", err)
	}
	if result.Version != 2 {
		t.Errorf("Version = %d, want 2", result.Version)
	}
}

func TestRemoveDevice_StoreUpdateError(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	secondDev := validDevice()
	secondDev.ID = 2
	acct.Devices = append(acct.Devices, secondDev)
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	store.updateErr = &VersionConflictError{AccountUUID: acct.UUID}

	_, err := m.RemoveDevice(ctx, acct.UUID, 2)
	if err == nil {
		t.Fatal("expected error from store.Update")
	}
}

// --- SetDeviceAttributes ---

func TestSetDeviceAttributes_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	fetchTrue := true
	attrs := DeviceAttributes{
		Name:              "My Phone",
		GcmRegistrationID: "gcm-id-123",
		FetchesMessages:   &fetchTrue,
	}

	result, err := m.SetDeviceAttributes(ctx, acct.UUID, PrimaryDeviceID, attrs)
	if err != nil {
		t.Fatalf("SetDeviceAttributes() error = %v", err)
	}

	dev := result.GetDevice(PrimaryDeviceID)
	if dev == nil {
		t.Fatal("primary device not found")
		return
	}
	if dev.Name != "My Phone" {
		t.Errorf("Name = %q, want %q", dev.Name, "My Phone")
	}
	if dev.GcmRegistrationID != "gcm-id-123" {
		t.Errorf("GcmRegistrationID = %q, want %q", dev.GcmRegistrationID, "gcm-id-123")
	}
	if !dev.FetchesMessages {
		t.Error("FetchesMessages should be true")
	}
	if dev.LastSeen.IsZero() {
		t.Error("LastSeen should be updated")
	}
}

func TestSetDeviceAttributes_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.SetDeviceAttributes(context.Background(), "", 1, DeviceAttributes{})
	assertInvalidArgErr(t, err, "uuid")
}

func TestSetDeviceAttributes_AccountNotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.SetDeviceAttributes(context.Background(), "nonexistent", 1, DeviceAttributes{})
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestSetDeviceAttributes_DeviceNotFound(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	_, err := m.SetDeviceAttributes(ctx, acct.UUID, 99, DeviceAttributes{})
	var target *DeviceNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected DeviceNotFoundError, got %T: %v", err, err)
	}
}

func TestSetDeviceAttributes_AllFields(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	fetchFalse := false
	caps := DeviceCapabilities{Storage: true, Transfer: true}
	spk := &SignedPreKey{KeyID: 10, PublicKey: []byte("new-pub"), Signature: []byte("new-sig")}
	kpk := &KyberPreKey{KeyID: 20, PublicKey: []byte("kyber-pub"), Signature: []byte("kyber-sig")}

	attrs := DeviceAttributes{
		Name:                  "Tablet",
		GcmRegistrationID:     "gcm-new",
		ApnRegistrationID:     "apn-new",
		VoipApnRegistrationID: "voip-new",
		FetchesMessages:       &fetchFalse,
		Capabilities:          &caps,
		SignedPreKey:          spk,
		KyberPreKey:           kpk,
	}

	result, err := m.SetDeviceAttributes(ctx, acct.UUID, PrimaryDeviceID, attrs)
	if err != nil {
		t.Fatalf("SetDeviceAttributes() error = %v", err)
	}

	dev := result.GetDevice(PrimaryDeviceID)
	if dev.Name != "Tablet" {
		t.Errorf("Name = %q, want %q", dev.Name, "Tablet")
	}
	if dev.ApnRegistrationID != "apn-new" {
		t.Errorf("ApnRegistrationID = %q, want %q", dev.ApnRegistrationID, "apn-new")
	}
	if dev.VoipApnRegistrationID != "voip-new" {
		t.Errorf("VoipApnRegistrationID = %q, want %q", dev.VoipApnRegistrationID, "voip-new")
	}
	if dev.FetchesMessages {
		t.Error("FetchesMessages should be false")
	}
	if !dev.Capabilities.Storage {
		t.Error("Capabilities.Storage should be true")
	}
	if dev.SignedPreKey.KeyID != 10 {
		t.Errorf("SignedPreKey.KeyID = %d, want 10", dev.SignedPreKey.KeyID)
	}
	if dev.KyberPreKey.KeyID != 20 {
		t.Errorf("KyberPreKey.KeyID = %d, want 20", dev.KyberPreKey.KeyID)
	}
}

func TestSetDeviceAttributes_PartialUpdate(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	acct.Devices[0].Name = "OriginalName"
	acct.Devices[0].GcmRegistrationID = "original-gcm"
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Only update name, leave other fields alone.
	attrs := DeviceAttributes{Name: "NewName"}
	result, err := m.SetDeviceAttributes(ctx, acct.UUID, PrimaryDeviceID, attrs)
	if err != nil {
		t.Fatalf("SetDeviceAttributes() error = %v", err)
	}

	dev := result.GetDevice(PrimaryDeviceID)
	if dev.Name != "NewName" {
		t.Errorf("Name = %q, want %q", dev.Name, "NewName")
	}
	if dev.GcmRegistrationID != "original-gcm" {
		t.Errorf("GcmRegistrationID = %q, want %q (should not have changed)", dev.GcmRegistrationID, "original-gcm")
	}
}

func TestSetDeviceAttributes_StoreUpdateError(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	store.updateErr = &VersionConflictError{AccountUUID: acct.UUID}

	_, err := m.SetDeviceAttributes(ctx, acct.UUID, PrimaryDeviceID, DeviceAttributes{Name: "test"})
	if err == nil {
		t.Fatal("expected error from store.Update")
	}
}

func TestSetDeviceAttributes_VersionIncrement(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	result, err := m.SetDeviceAttributes(ctx, acct.UUID, PrimaryDeviceID, DeviceAttributes{Name: "x"})
	if err != nil {
		t.Fatalf("SetDeviceAttributes() error = %v", err)
	}
	if result.Version != 2 {
		t.Errorf("Version = %d, want 2", result.Version)
	}
}

// --- SetRegistrationLock ---

func TestSetRegistrationLock_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := m.SetRegistrationLock(ctx, acct.UUID, "my-pin"); err != nil {
		t.Fatalf("SetRegistrationLock() error = %v", err)
	}

	got, _ := m.Get(ctx, acct.UUID)
	if got.RegistrationLockHash == nil {
		t.Fatal("RegistrationLockHash should be set after SetRegistrationLock")
	}
	// The stored hash must verify against the original PIN.
	if !got.RegistrationLockHash.Verify("my-pin") {
		t.Error("RegistrationLockHash.Verify returned false for the original PIN")
	}
	// The stored hash must not verify against a wrong PIN.
	if got.RegistrationLockHash.Verify("wrong-pin") {
		t.Error("RegistrationLockHash.Verify returned true for a wrong PIN")
	}
}

func TestSetRegistrationLock_StoresHashedPIN(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	pin := "argon2id-test-pin"
	if err := m.SetRegistrationLock(ctx, acct.UUID, pin); err != nil {
		t.Fatalf("SetRegistrationLock() error = %v", err)
	}

	got, _ := m.Get(ctx, acct.UUID)
	if got.RegistrationLockHash == nil {
		t.Fatal("RegistrationLockHash must not be nil after setting a PIN")
	}
	// The hash field must not contain the plaintext PIN.
	if got.RegistrationLockHash.Hash == pin {
		t.Error("RegistrationLockHash.Hash must not equal the plaintext PIN")
	}
	if got.RegistrationLockHash.Salt == "" {
		t.Error("RegistrationLockHash.Salt must not be empty")
	}
}

func TestSetRegistrationLock_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.SetRegistrationLock(context.Background(), "", "pin")
	assertInvalidArgErr(t, err, "uuid")
}

func TestSetRegistrationLock_EmptyPin(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.SetRegistrationLock(context.Background(), "uuid-1", "")
	assertInvalidArgErr(t, err, "pin")
}

func TestSetRegistrationLock_AccountNotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.SetRegistrationLock(context.Background(), "nonexistent", "pin")
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestSetRegistrationLock_VersionIncrement(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := m.SetRegistrationLock(ctx, acct.UUID, "pin"); err != nil {
		t.Fatalf("SetRegistrationLock() error = %v", err)
	}

	got, _ := m.Get(ctx, acct.UUID)
	if got.Version != 2 {
		t.Errorf("Version = %d, want 2", got.Version)
	}
}

func TestSetRegistrationLock_StoreUpdateError(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	store.updateErr = &VersionConflictError{AccountUUID: acct.UUID}

	err := m.SetRegistrationLock(ctx, acct.UUID, "pin")
	if err == nil {
		t.Fatal("expected error from store.Update")
	}
}

// --- ClearRegistrationLock ---

func TestClearRegistrationLock_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := m.SetRegistrationLock(ctx, acct.UUID, "pin"); err != nil {
		t.Fatalf("SetRegistrationLock() error = %v", err)
	}

	if err := m.ClearRegistrationLock(ctx, acct.UUID); err != nil {
		t.Fatalf("ClearRegistrationLock() error = %v", err)
	}

	got, _ := m.Get(ctx, acct.UUID)
	if got.RegistrationLockHash != nil {
		t.Error("RegistrationLockHash should be nil after ClearRegistrationLock")
	}
}

func TestClearRegistrationLock_RemovesHash(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := m.SetRegistrationLock(ctx, acct.UUID, "pin"); err != nil {
		t.Fatalf("SetRegistrationLock() error = %v", err)
	}

	// Verify the lock is present before clearing.
	before, _ := m.Get(ctx, acct.UUID)
	if before.RegistrationLockHash == nil {
		t.Fatal("expected RegistrationLockHash to be set before clearing")
	}

	if err := m.ClearRegistrationLock(ctx, acct.UUID); err != nil {
		t.Fatalf("ClearRegistrationLock() error = %v", err)
	}

	after, _ := m.Get(ctx, acct.UUID)
	if after.RegistrationLockHash != nil {
		t.Error("RegistrationLockHash must be nil after ClearRegistrationLock")
	}
}

func TestClearRegistrationLock_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.ClearRegistrationLock(context.Background(), "")
	assertInvalidArgErr(t, err, "uuid")
}

func TestClearRegistrationLock_AccountNotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.ClearRegistrationLock(context.Background(), "nonexistent")
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestClearRegistrationLock_VersionIncrement(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := m.ClearRegistrationLock(ctx, acct.UUID); err != nil {
		t.Fatalf("ClearRegistrationLock() error = %v", err)
	}

	got, _ := m.Get(ctx, acct.UUID)
	if got.Version != 2 {
		t.Errorf("Version = %d, want 2", got.Version)
	}
}

// --- ChangeNumber ---

func TestChangeNumber_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	pniKey := []byte("new-pni-identity-key")
	updated, err := m.ChangeNumber(ctx, acct.UUID, "+15559999999", pniKey)
	if err != nil {
		t.Fatalf("ChangeNumber: %v", err)
	}
	if updated.Number != "+15559999999" {
		t.Errorf("Number = %q, want +15559999999", updated.Number)
	}
	if string(updated.PhoneNumberIdentityKey) != string(pniKey) {
		t.Errorf("PhoneNumberIdentityKey not updated")
	}
}

func TestChangeNumber_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.ChangeNumber(context.Background(), "", "+15559999999", nil)
	if err == nil {
		t.Fatal("expected error for empty UUID")
	}
	var invalidArg *InvalidArgumentError
	if !errors.As(err, &invalidArg) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
}

func TestChangeNumber_EmptyNumber(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.ChangeNumber(context.Background(), "uuid-1", "", nil)
	if err == nil {
		t.Fatal("expected error for empty number")
	}
	var invalidArg *InvalidArgumentError
	if !errors.As(err, &invalidArg) {
		t.Fatalf("expected *InvalidArgumentError, got %T", err)
	}
}

func TestChangeNumber_AccountNotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.ChangeNumber(context.Background(), "nonexistent", "+15559999999", nil)
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}
	var notFound *AccountNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("expected *AccountNotFoundError, got %T", err)
	}
}

func TestChangeNumber_NilPniKey(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	acct.PhoneNumberIdentityKey = []byte("original-pni-key")
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated, err := m.ChangeNumber(ctx, acct.UUID, "+15559999999", nil)
	if err != nil {
		t.Fatalf("ChangeNumber: %v", err)
	}
	// PNI key should remain unchanged when nil is passed.
	if string(updated.PhoneNumberIdentityKey) != "original-pni-key" {
		t.Errorf("PhoneNumberIdentityKey was unexpectedly changed")
	}
}

func TestChangeNumber_VersionIncrement(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	before, _ := m.Get(ctx, acct.UUID)
	versionBefore := before.Version

	_, err := m.ChangeNumber(ctx, acct.UUID, "+15559999999", nil)
	if err != nil {
		t.Fatalf("ChangeNumber: %v", err)
	}

	after, _ := m.Get(ctx, acct.UUID)
	if after.Version != versionBefore+1 {
		t.Errorf("Version = %d, want %d", after.Version, versionBefore+1)
	}
}

func TestChangeNumber_StoreUpdateError(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	store.updateErr = errors.New("simulated store error")
	_, err := m.ChangeNumber(ctx, acct.UUID, "+15559999999", nil)
	if err == nil {
		t.Fatal("expected error when store update fails")
	}
}

// --- SetPhoneNumberDiscoverability ---

func TestSetPhoneNumberDiscoverability_EnableSuccess(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := m.SetPhoneNumberDiscoverability(ctx, acct.UUID, true); err != nil {
		t.Fatalf("SetPhoneNumberDiscoverability() error = %v", err)
	}

	got, _ := m.Get(ctx, acct.UUID)
	if !got.DiscoverableByPhoneNumber {
		t.Error("DiscoverableByPhoneNumber should be true")
	}
}

func TestSetPhoneNumberDiscoverability_DisableSuccess(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	acct.DiscoverableByPhoneNumber = true
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := m.SetPhoneNumberDiscoverability(ctx, acct.UUID, false); err != nil {
		t.Fatalf("SetPhoneNumberDiscoverability() error = %v", err)
	}

	got, _ := m.Get(ctx, acct.UUID)
	if got.DiscoverableByPhoneNumber {
		t.Error("DiscoverableByPhoneNumber should be false")
	}
}

func TestSetPhoneNumberDiscoverability_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.SetPhoneNumberDiscoverability(context.Background(), "", true)
	assertInvalidArgErr(t, err, "uuid")
}

func TestSetPhoneNumberDiscoverability_AccountNotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.SetPhoneNumberDiscoverability(context.Background(), "nonexistent", true)
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestSetPhoneNumberDiscoverability_VersionIncrement(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := m.SetPhoneNumberDiscoverability(ctx, acct.UUID, true); err != nil {
		t.Fatalf("SetPhoneNumberDiscoverability() error = %v", err)
	}

	got, _ := m.Get(ctx, acct.UUID)
	if got.Version != 2 {
		t.Errorf("Version = %d, want 2", got.Version)
	}
}

// --- GetDataReport ---

func TestGetDataReport_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	secondDev := validDevice()
	secondDev.ID = 2
	acct.Devices = append(acct.Devices, secondDev)
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	report, err := m.GetDataReport(ctx, acct.UUID)
	if err != nil {
		t.Fatalf("GetDataReport() error = %v", err)
	}
	if report.UUID != acct.UUID {
		t.Errorf("UUID = %q, want %q", report.UUID, acct.UUID)
	}
	if report.Number != acct.Number {
		t.Errorf("Number = %q, want %q", report.Number, acct.Number)
	}
	if len(report.Devices) != 2 {
		t.Fatalf("Devices count = %d, want 2", len(report.Devices))
	}
	if report.Devices[0] != 1 || report.Devices[1] != 2 {
		t.Errorf("Devices = %v, want [1 2]", report.Devices)
	}
}

func TestGetDataReport_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.GetDataReport(context.Background(), "")
	assertInvalidArgErr(t, err, "uuid")
}

func TestGetDataReport_AccountNotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.GetDataReport(context.Background(), "nonexistent")
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestGetDataReport_SingleDevice(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	report, err := m.GetDataReport(ctx, acct.UUID)
	if err != nil {
		t.Fatalf("GetDataReport() error = %v", err)
	}
	if len(report.Devices) != 1 {
		t.Errorf("Devices count = %d, want 1", len(report.Devices))
	}
}

// --- applyDeviceAttributes ---

func TestApplyDeviceAttributes_EmptyAttributes(t *testing.T) {
	d := &Device{
		Name:              "original",
		GcmRegistrationID: "gcm-orig",
		FetchesMessages:   true,
	}
	applyDeviceAttributes(d, DeviceAttributes{})

	if d.Name != "original" {
		t.Errorf("Name changed to %q, should remain %q", d.Name, "original")
	}
	if d.GcmRegistrationID != "gcm-orig" {
		t.Errorf("GcmRegistrationID changed to %q, should remain %q", d.GcmRegistrationID, "gcm-orig")
	}
	if !d.FetchesMessages {
		t.Error("FetchesMessages changed, should remain true")
	}
}

func TestApplyDeviceAttributes_AllFields(t *testing.T) {
	d := &Device{}
	fetchTrue := true
	caps := DeviceCapabilities{Storage: true}
	spk := &SignedPreKey{KeyID: 5}
	kpk := &KyberPreKey{KeyID: 6}

	attrs := DeviceAttributes{
		Name:                  "new-name",
		GcmRegistrationID:     "new-gcm",
		ApnRegistrationID:     "new-apn",
		VoipApnRegistrationID: "new-voip",
		FetchesMessages:       &fetchTrue,
		Capabilities:          &caps,
		SignedPreKey:          spk,
		KyberPreKey:           kpk,
	}

	applyDeviceAttributes(d, attrs)

	if d.Name != "new-name" {
		t.Errorf("Name = %q, want %q", d.Name, "new-name")
	}
	if d.GcmRegistrationID != "new-gcm" {
		t.Errorf("GcmRegistrationID = %q, want %q", d.GcmRegistrationID, "new-gcm")
	}
	if d.ApnRegistrationID != "new-apn" {
		t.Errorf("ApnRegistrationID = %q, want %q", d.ApnRegistrationID, "new-apn")
	}
	if d.VoipApnRegistrationID != "new-voip" {
		t.Errorf("VoipApnRegistrationID = %q, want %q", d.VoipApnRegistrationID, "new-voip")
	}
	if !d.FetchesMessages {
		t.Error("FetchesMessages should be true")
	}
	if !d.Capabilities.Storage {
		t.Error("Capabilities.Storage should be true")
	}
	if d.SignedPreKey.KeyID != 5 {
		t.Errorf("SignedPreKey.KeyID = %d, want 5", d.SignedPreKey.KeyID)
	}
	if d.KyberPreKey.KeyID != 6 {
		t.Errorf("KyberPreKey.KeyID = %d, want 6", d.KyberPreKey.KeyID)
	}
}

func TestApplyDeviceAttributes_FetchesMessagesFalse(t *testing.T) {
	d := &Device{FetchesMessages: true}
	fetchFalse := false
	applyDeviceAttributes(d, DeviceAttributes{FetchesMessages: &fetchFalse})
	if d.FetchesMessages {
		t.Error("FetchesMessages should be false")
	}
}

// --- validateDevice ---

func TestValidateDevice_Valid(t *testing.T) {
	d := &Device{
		AuthToken:    "tok",
		SignedPreKey: &SignedPreKey{PublicKey: []byte("k"), Signature: []byte("s")},
	}
	if err := validateDevice(d); err != nil {
		t.Errorf("validateDevice() error = %v, want nil", err)
	}
}

func TestValidateDevice_MissingAuthToken(t *testing.T) {
	d := &Device{
		SignedPreKey: &SignedPreKey{PublicKey: []byte("k"), Signature: []byte("s")},
	}
	err := validateDevice(d)
	assertInvalidArgErr(t, err, "device.authToken")
}

func TestValidateDevice_MissingSignedPreKey(t *testing.T) {
	d := &Device{AuthToken: "tok"}
	err := validateDevice(d)
	assertInvalidArgErr(t, err, "device.signedPreKey")
}

func TestValidateDevice_EmptyPublicKey(t *testing.T) {
	d := &Device{
		AuthToken:    "tok",
		SignedPreKey: &SignedPreKey{PublicKey: nil, Signature: []byte("s")},
	}
	err := validateDevice(d)
	assertInvalidArgErr(t, err, "device.signedPreKey.publicKey")
}

func TestValidateDevice_EmptySignature(t *testing.T) {
	d := &Device{
		AuthToken:    "tok",
		SignedPreKey: &SignedPreKey{PublicKey: []byte("k"), Signature: nil},
	}
	err := validateDevice(d)
	assertInvalidArgErr(t, err, "device.signedPreKey.signature")
}

// --- validateAccountForCreation ---

func TestValidateAccountForCreation_Valid(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	if err := m.validateAccountForCreation(acct); err != nil {
		t.Errorf("validateAccountForCreation() error = %v, want nil", err)
	}
}

func TestValidateAccountForCreation_NilAccount(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.validateAccountForCreation(nil)
	assertInvalidArgErr(t, err, "account")
}

func TestValidateAccountForCreation_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.UUID = ""
	err := m.validateAccountForCreation(acct)
	assertInvalidArgErr(t, err, "uuid")
}

func TestValidateAccountForCreation_EmptyNumber(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.Number = ""
	err := m.validateAccountForCreation(acct)
	assertInvalidArgErr(t, err, "number")
}

func TestValidateAccountForCreation_EmptyIdentityKey(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.IdentityKey = nil
	err := m.validateAccountForCreation(acct)
	assertInvalidArgErr(t, err, "identityKey")
}

func TestValidateAccountForCreation_NoDevices(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.Devices = nil
	err := m.validateAccountForCreation(acct)
	assertInvalidArgErr(t, err, "devices")
}

func TestValidateAccountForCreation_NoPrimaryDevice(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.Devices[0].ID = 5
	err := m.validateAccountForCreation(acct)
	assertInvalidArgErr(t, err, "devices")
}

func TestValidateAccountForCreation_InvalidPrimaryDevice(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	acct := validAccount()
	acct.Devices[0].AuthToken = "" // invalid device
	err := m.validateAccountForCreation(acct)
	assertInvalidArgErr(t, err, "device.authToken")
}

// --- hashDeviceAuthToken ---

// TestHashDeviceAuthToken_EmptyToken verifies that a device with an empty
// AuthToken is a no-op: the function must return nil and leave AuthTokenHash
// unset, because empty tokens are filtered upstream by validateDevice.
func TestHashDeviceAuthToken_EmptyToken(t *testing.T) {
	d := &Device{AuthToken: ""}
	err := hashDeviceAuthToken(d)
	if err != nil {
		t.Fatalf("hashDeviceAuthToken with empty token returned error: %v", err)
	}
	if d.AuthTokenHash != nil {
		t.Error("expected AuthTokenHash to be nil for empty token")
	}
}

// TestHashDeviceAuthToken_ValidToken verifies that a non-empty AuthToken
// produces a non-nil AuthTokenHash and that the original token can be verified
// against it.
func TestHashDeviceAuthToken_ValidToken(t *testing.T) {
	const token = "my-secure-auth-token"
	d := &Device{AuthToken: token}
	err := hashDeviceAuthToken(d)
	if err != nil {
		t.Fatalf("hashDeviceAuthToken returned unexpected error: %v", err)
	}
	if d.AuthTokenHash == nil {
		t.Fatal("expected AuthTokenHash to be set, got nil")
	}
	if !d.AuthTokenHash.Verify([]byte(token)) {
		t.Error("Verify returned false for the original token")
	}
}

// TestHashDeviceAuthToken_HashDoesNotMatchWrongToken confirms that the derived
// hash does not verify against a different token value.
func TestHashDeviceAuthToken_HashDoesNotMatchWrongToken(t *testing.T) {
	d := &Device{AuthToken: "correct-token"}
	if err := hashDeviceAuthToken(d); err != nil {
		t.Fatalf("hashDeviceAuthToken returned error: %v", err)
	}
	if d.AuthTokenHash.Verify([]byte("wrong-token")) {
		t.Error("Verify must return false for the wrong token")
	}
}

// TestHashDeviceAuthToken_AuthTokenPreserved confirms that AuthToken is left
// intact on the struct after hashing so callers can still read the plaintext
// value transiently.
func TestHashDeviceAuthToken_AuthTokenPreserved(t *testing.T) {
	const token = "preserved-token"
	d := &Device{AuthToken: token}
	if err := hashDeviceAuthToken(d); err != nil {
		t.Fatalf("hashDeviceAuthToken returned error: %v", err)
	}
	if d.AuthToken != token {
		t.Errorf("AuthToken = %q, want %q", d.AuthToken, token)
	}
}

// --- RecreatePreserving ---

func TestRecreatePreserving_NilAccount(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.RecreatePreserving(context.Background(), nil)
	assertInvalidArgErr(t, err, "account")
}

func TestRecreatePreserving_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	err := m.RecreatePreserving(context.Background(), &Account{})
	assertInvalidArgErr(t, err, "uuid")
}

func TestRecreatePreserving_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := &Account{
		UUID:    "preserve-uuid",
		Number:  "+15550000001",
		Version: 42,
	}
	if err := m.RecreatePreserving(ctx, acct); err != nil {
		t.Fatalf("RecreatePreserving: %v", err)
	}
	got, err := store.Get(ctx, "preserve-uuid")
	if err != nil {
		t.Fatalf("Get after RecreatePreserving: %v", err)
	}
	if got.Version != 42 {
		t.Errorf("Version = %d, want 42", got.Version)
	}
}

func TestRecreatePreserving_StoreError(t *testing.T) {
	store := newMemoryStore()
	store.createErr = errors.New("store create error")
	m := NewAccountsManager(store, 0)

	err := m.RecreatePreserving(context.Background(), &Account{UUID: "some-uuid"})
	if err == nil || err.Error() != "store create error" {
		t.Errorf("expected store error, got: %v", err)
	}
}

// --- ClearGcmRegistration / ClearApnRegistration / clearDevicePush ---

func TestClearGcmRegistration_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	acct.Devices[0].GcmRegistrationID = "gcm-token-123"
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := m.ClearGcmRegistration(ctx, acct.UUID, PrimaryDeviceID)
	if err != nil {
		t.Fatalf("ClearGcmRegistration: %v", err)
	}
	if got.GetDevice(PrimaryDeviceID).GcmRegistrationID != "" {
		t.Error("expected GcmRegistrationID to be cleared")
	}
}

func TestClearGcmRegistration_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.ClearGcmRegistration(context.Background(), "", 1)
	assertInvalidArgErr(t, err, "uuid")
}

func TestClearGcmRegistration_DeviceNotFound(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err := m.ClearGcmRegistration(ctx, acct.UUID, 999)
	var target *DeviceNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected DeviceNotFoundError, got: %v", err)
	}
}

func TestClearApnRegistration_Success(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	acct.Devices[0].ApnRegistrationID = "apn-token"
	acct.Devices[0].VoipApnRegistrationID = "voip-apn-token"
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := m.ClearApnRegistration(ctx, acct.UUID, PrimaryDeviceID)
	if err != nil {
		t.Fatalf("ClearApnRegistration: %v", err)
	}
	dev := got.GetDevice(PrimaryDeviceID)
	if dev.ApnRegistrationID != "" || dev.VoipApnRegistrationID != "" {
		t.Errorf("expected APN tokens cleared, got ApnRegistrationID=%q VoipApnRegistrationID=%q",
			dev.ApnRegistrationID, dev.VoipApnRegistrationID)
	}
}

func TestClearApnRegistration_EmptyUUID(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.ClearApnRegistration(context.Background(), "", 1)
	assertInvalidArgErr(t, err, "uuid")
}

func TestClearGcmRegistration_AccountNotFound(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	_, err := m.ClearGcmRegistration(context.Background(), "nonexistent-uuid", 1)
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Errorf("expected AccountNotFoundError, got: %v", err)
	}
}

// --- ListAll ---

func TestListAll_Empty(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	var visited []*Account
	err := m.ListAll(context.Background(), func(a *Account) error {
		visited = append(visited, a)
		return nil
	})
	if err != nil {
		t.Fatalf("ListAll on empty store: %v", err)
	}
	if len(visited) != 0 {
		t.Errorf("expected 0 accounts, got %d", len(visited))
	}
}

func TestListAll_MultipleAccounts(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	for i, n := range []string{"+15550000001", "+15550000002", "+15550000003"} {
		a := validAccount()
		a.UUID = "uuid-" + n
		a.Number = n
		_ = i
		if err := m.Create(ctx, a); err != nil {
			t.Fatalf("Create %s: %v", n, err)
		}
	}

	var uuids []string
	err := m.ListAll(ctx, func(a *Account) error {
		uuids = append(uuids, a.UUID)
		return nil
	})
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(uuids) != 3 {
		t.Errorf("expected 3 accounts, got %d", len(uuids))
	}
}

func TestListAll_CallbackError(t *testing.T) {
	store := newMemoryStore()
	m := NewAccountsManager(store, 0)
	ctx := context.Background()

	acct := validAccount()
	if err := m.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	sentinel := errors.New("callback error")
	err := m.ListAll(ctx, func(_ *Account) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got: %v", err)
	}
}

// --- helpers ---

func assertInvalidArgErr(t *testing.T, err error, expectedField string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected InvalidArgumentError for field %q, got nil", expectedField)
	}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
	if target.Field != expectedField {
		t.Errorf("InvalidArgumentError.Field = %q, want %q", target.Field, expectedField)
	}
}
