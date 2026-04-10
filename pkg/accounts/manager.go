package accounts

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/auth"
)

// DefaultMaxDevices is the maximum number of linked devices per account when
// no explicit limit is configured.
const DefaultMaxDevices = 6

// AccountsManager coordinates account lifecycle operations, delegating
// persistence to an AccountStore and enforcing business rules.
type AccountsManager struct {
	store      AccountStore
	maxDevices int
}

// NewAccountsManager creates a new AccountsManager backed by the given store.
// The maxDevices parameter controls the maximum number of devices allowed per
// account; if zero, DefaultMaxDevices is used.
func NewAccountsManager(store AccountStore, maxDevices int) *AccountsManager {
	if maxDevices <= 0 {
		maxDevices = DefaultMaxDevices
	}
	return &AccountsManager{
		store:      store,
		maxDevices: maxDevices,
	}
}

// Create registers a new account. The caller must set UUID, Number,
// IdentityKey, and provide at least one device. The account's CreatedAt
// timestamp and Version are set automatically.
func (m *AccountsManager) Create(ctx context.Context, account *Account) error {
	if err := m.validateAccountForCreation(account); err != nil {
		return err
	}

	now := time.Now().UTC()
	account.CreatedAt = now
	account.Version = 1

	for i := range account.Devices {
		account.Devices[i].CreatedAt = now
		account.Devices[i].LastSeen = now
		if err := hashDeviceAuthToken(&account.Devices[i]); err != nil {
			return err
		}
	}

	return m.store.Create(ctx, account)
}

// Get retrieves an account by its UUID.
func (m *AccountsManager) Get(ctx context.Context, uuid string) (*Account, error) {
	if uuid == "" {
		return nil, &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	return m.store.Get(ctx, uuid)
}

// GetByNumber retrieves an account by its E.164 phone number.
func (m *AccountsManager) GetByNumber(ctx context.Context, number string) (*Account, error) {
	if number == "" {
		return nil, &InvalidArgumentError{Field: "number", Message: "must not be empty"}
	}
	return m.store.GetByNumber(ctx, number)
}

// Update persists changes to an existing account. The account's Version is
// incremented automatically before writing. Callers must not modify Version
// directly.
func (m *AccountsManager) Update(ctx context.Context, account *Account) error {
	if account == nil {
		return &InvalidArgumentError{Field: "account", Message: "must not be nil"}
	}
	if account.UUID == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}

	account.Version++

	return m.store.Update(ctx, account)
}

// Delete removes an account and all of its associated data by UUID.
func (m *AccountsManager) Delete(ctx context.Context, uuid string) error {
	if uuid == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	return m.store.Delete(ctx, uuid)
}

// AddDevice links a new device to the account identified by the given UUID.
// The device ID is assigned as one greater than the current maximum device ID
// on the account. The device limit is enforced before the device is added.
func (m *AccountsManager) AddDevice(ctx context.Context, uuid string, device *Device) (*Account, error) {
	if uuid == "" {
		return nil, &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	if device == nil {
		return nil, &InvalidArgumentError{Field: "device", Message: "must not be nil"}
	}
	if err := validateDevice(device); err != nil {
		return nil, err
	}

	account, err := m.store.Get(ctx, uuid)
	if err != nil {
		return nil, err
	}

	if len(account.Devices) >= m.maxDevices {
		return nil, &DeviceLimitExceededError{
			MaxDevices: m.maxDevices,
			Current:    len(account.Devices),
		}
	}

	// Assign the next available device ID.
	var maxID uint64
	for i := range account.Devices {
		if account.Devices[i].ID > maxID {
			maxID = account.Devices[i].ID
		}
	}
	device.ID = maxID + 1

	now := time.Now().UTC()
	device.CreatedAt = now
	device.LastSeen = now

	if err := hashDeviceAuthToken(device); err != nil {
		return nil, err
	}

	account.Devices = append(account.Devices, *device)
	account.Version++

	if err := m.store.Update(ctx, account); err != nil {
		return nil, err
	}

	return account, nil
}

// RemoveDevice unlinks a device from the account identified by the given UUID.
// Removing the primary device (ID 1) is not permitted.
func (m *AccountsManager) RemoveDevice(ctx context.Context, uuid string, deviceID uint64) (*Account, error) {
	if uuid == "" {
		return nil, &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	if deviceID == PrimaryDeviceID {
		return nil, &PrimaryDeviceRemovalError{AccountUUID: uuid}
	}

	account, err := m.store.Get(ctx, uuid)
	if err != nil {
		return nil, err
	}

	found := false
	devices := make([]Device, 0, len(account.Devices)-1)
	for i := range account.Devices {
		if account.Devices[i].ID == deviceID {
			found = true
			continue
		}
		devices = append(devices, account.Devices[i])
	}

	if !found {
		return nil, &DeviceNotFoundError{AccountUUID: uuid, DeviceID: deviceID}
	}

	account.Devices = devices
	account.Version++

	if err := m.store.Update(ctx, account); err != nil {
		return nil, err
	}

	return account, nil
}

// SetDeviceAttributes updates the mutable attributes of a specific device on
// an account. Only non-zero fields in the provided attributes are applied.
func (m *AccountsManager) SetDeviceAttributes(ctx context.Context, uuid string, deviceID uint64, attrs DeviceAttributes) (*Account, error) {
	if uuid == "" {
		return nil, &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}

	account, err := m.store.Get(ctx, uuid)
	if err != nil {
		return nil, err
	}

	device := account.GetDevice(deviceID)
	if device == nil {
		return nil, &DeviceNotFoundError{AccountUUID: uuid, DeviceID: deviceID}
	}

	applyDeviceAttributes(device, attrs)

	device.LastSeen = time.Now().UTC()
	account.Version++

	if err := m.store.Update(ctx, account); err != nil {
		return nil, err
	}

	return account, nil
}

// SetRegistrationLock hashes pin with Argon2id and stores the derived hash on
// the account identified by uuid. The PIN must not be empty; callers should
// validate length and character constraints before invoking this method.
func (m *AccountsManager) SetRegistrationLock(ctx context.Context, uuid, pin string) error {
	if uuid == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	if pin == "" {
		return &InvalidArgumentError{Field: "pin", Message: "must not be empty"}
	}

	account, err := m.store.Get(ctx, uuid)
	if err != nil {
		return err
	}

	lockHash, err := auth.HashRegistrationLock(pin)
	if err != nil {
		return &RegistrationLockError{AccountUUID: uuid, Cause: err}
	}

	account.RegistrationLockHash = lockHash
	account.Version++

	return m.store.Update(ctx, account)
}

// ClearRegistrationLock removes the registration lock from the account
// identified by the given UUID.
func (m *AccountsManager) ClearRegistrationLock(ctx context.Context, uuid string) error {
	if uuid == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}

	account, err := m.store.Get(ctx, uuid)
	if err != nil {
		return err
	}

	account.RegistrationLockHash = nil
	account.Version++

	return m.store.Update(ctx, account)
}

// ChangeNumber updates the phone number for the account identified by the given
// UUID. If a PNI identity key is provided, it replaces the existing one. The
// account version is incremented automatically.
//
// If the target number is already owned by a different account, that account is
// deleted first (mirroring the Java Signal-Server behaviour where proving
// ownership of a number via verification displaces the previous holder).
func (m *AccountsManager) ChangeNumber(ctx context.Context, uuid, newNumber string, pniIdentityKey []byte) (*Account, error) {
	if uuid == "" {
		return nil, &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	if newNumber == "" {
		return nil, &InvalidArgumentError{Field: "number", Message: "must not be empty"}
	}

	account, err := m.store.Get(ctx, uuid)
	if err != nil {
		return nil, err
	}

	// If another account owns the target number, delete it. The caller has
	// already proved ownership of the number through the verification flow.
	existing, err := m.store.GetByNumber(ctx, newNumber)
	if err == nil && existing != nil && existing.UUID != uuid {
		if delErr := m.store.Delete(ctx, existing.UUID); delErr != nil {
			return nil, delErr
		}
	}

	account.Number = newNumber
	if len(pniIdentityKey) > 0 {
		account.PhoneNumberIdentityKey = pniIdentityKey
	}
	account.Version++

	if err := m.store.Update(ctx, account); err != nil {
		return nil, err
	}

	return account, nil
}

// SetPhoneNumberDiscoverability sets whether the account identified by the
// given UUID is discoverable by phone number.
func (m *AccountsManager) SetPhoneNumberDiscoverability(ctx context.Context, uuid string, discoverable bool) error {
	if uuid == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}

	account, err := m.store.Get(ctx, uuid)
	if err != nil {
		return err
	}

	account.DiscoverableByPhoneNumber = discoverable
	account.Version++

	return m.store.Update(ctx, account)
}

// GetDataReport returns a summary of the account data for the account
// identified by the given UUID.
func (m *AccountsManager) GetDataReport(ctx context.Context, uuid string) (*DataReport, error) {
	if uuid == "" {
		return nil, &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}

	account, err := m.store.Get(ctx, uuid)
	if err != nil {
		return nil, err
	}

	deviceIDs := make([]uint64, len(account.Devices))
	for i := range account.Devices {
		deviceIDs[i] = account.Devices[i].ID
	}

	return &DataReport{
		UUID:    account.UUID,
		Number:  account.Number,
		Devices: deviceIDs,
	}, nil
}

// DeviceAttributes carries the fields that may be updated on an existing
// device. Only non-zero-value fields are applied during SetDeviceAttributes.
type DeviceAttributes struct {
	Name                  string
	GcmRegistrationID     string
	ApnRegistrationID     string
	VoipApnRegistrationID string
	RegistrationID        *uint32
	FetchesMessages       *bool
	Capabilities          *DeviceCapabilities
	SignedPreKey          *SignedPreKey
	KyberPreKey           *KyberPreKey
}

// applyDeviceAttributes merges non-zero attribute values into the target
// device.
func applyDeviceAttributes(d *Device, attrs DeviceAttributes) {
	if attrs.Name != "" {
		d.Name = attrs.Name
	}
	if attrs.GcmRegistrationID != "" {
		d.GcmRegistrationID = attrs.GcmRegistrationID
	}
	if attrs.ApnRegistrationID != "" {
		d.ApnRegistrationID = attrs.ApnRegistrationID
	}
	if attrs.VoipApnRegistrationID != "" {
		d.VoipApnRegistrationID = attrs.VoipApnRegistrationID
	}
	if attrs.FetchesMessages != nil {
		d.FetchesMessages = *attrs.FetchesMessages
	}
	if attrs.Capabilities != nil {
		d.Capabilities = *attrs.Capabilities
	}
	if attrs.SignedPreKey != nil {
		d.SignedPreKey = attrs.SignedPreKey
	}
	if attrs.KyberPreKey != nil {
		d.KyberPreKey = attrs.KyberPreKey
	}
}

// validateAccountForCreation checks that all required fields are present on a
// new account.
func (m *AccountsManager) validateAccountForCreation(account *Account) error {
	if account == nil {
		return &InvalidArgumentError{Field: "account", Message: "must not be nil"}
	}
	if account.UUID == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	if account.Number == "" {
		return &InvalidArgumentError{Field: "number", Message: "must not be empty"}
	}
	if len(account.IdentityKey) == 0 {
		return &InvalidArgumentError{Field: "identityKey", Message: "must not be empty"}
	}
	if len(account.Devices) == 0 {
		return &InvalidArgumentError{Field: "devices", Message: "at least one device is required"}
	}

	primary := account.GetDevice(PrimaryDeviceID)
	if primary == nil {
		return &InvalidArgumentError{Field: "devices", Message: "primary device (ID 1) is required"}
	}

	return validateDevice(primary)
}

// validateDevice checks that a device has the minimum required fields to be
// considered valid. AuthToken must be present on the input device; it is
// hashed into AuthTokenHash by hashDeviceAuthToken before persistence.
func validateDevice(d *Device) error {
	if d.AuthToken == "" {
		return &InvalidArgumentError{Field: "device.authToken", Message: "must not be empty"}
	}
	if d.SignedPreKey == nil {
		return &InvalidArgumentError{Field: "device.signedPreKey", Message: "must not be nil"}
	}
	if len(d.SignedPreKey.PublicKey) == 0 {
		return &InvalidArgumentError{Field: "device.signedPreKey.publicKey", Message: "must not be empty"}
	}
	if len(d.SignedPreKey.Signature) == 0 {
		return &InvalidArgumentError{Field: "device.signedPreKey.signature", Message: "must not be empty"}
	}
	return nil
}

// hashDeviceAuthToken derives AuthTokenHash from AuthToken using
// auth.NewSaltedTokenHash. AuthToken is left intact on the struct so that
// the caller can still access the plaintext value transiently, but only
// AuthTokenHash is persisted.
func hashDeviceAuthToken(d *Device) error {
	if d.AuthToken == "" {
		return nil
	}
	h, err := auth.NewSaltedTokenHash(d.AuthToken)
	if err != nil {
		return &InvalidArgumentError{Field: "device.authToken", Message: err.Error()}
	}
	d.AuthTokenHash = h
	return nil
}
