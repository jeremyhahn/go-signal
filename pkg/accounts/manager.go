package accounts

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

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
	// bus, when non-nil, receives a DirectoryEvent after every
	// successful mutation. The directory gRPC service subscribes to
	// it to drive change replication into cdsi.
	bus *DirectoryEventBus
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

// SetDirectoryEventBus attaches a publish-only event bus to the
// manager. Every successful Create/Update/Delete pathway publishes
// to the bus after the underlying store has committed. Passing nil
// detaches the bus. Safe to call before serving traffic; not safe to
// call concurrently with mutating operations.
func (m *AccountsManager) SetDirectoryEventBus(bus *DirectoryEventBus) {
	m.bus = bus
}

// publishCreated emits a Created event when a bus is attached.
func (m *AccountsManager) publishCreated(account *Account) {
	if m.bus != nil && account != nil {
		m.bus.Publish(DirectoryEventCreated, account.UUID, account)
	}
}

// publishUpdated emits an Updated event when a bus is attached.
func (m *AccountsManager) publishUpdated(account *Account) {
	if m.bus != nil && account != nil {
		m.bus.Publish(DirectoryEventUpdated, account.UUID, account)
	}
}

// publishDeleted emits a Deleted event when a bus is attached. The
// snapshot is the account's pre-delete state — required so consumers
// can resolve UUID → E164 for index removal. Callers that don't have
// it (e.g. delete-by-UUID with no prior read) pass nil; consumers
// must then fall back to a full snapshot resync.
func (m *AccountsManager) publishDeleted(uuid string, snapshot *Account) {
	if m.bus != nil {
		m.bus.Publish(DirectoryEventDeleted, uuid, snapshot)
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

	// Generate a PNI if the caller hasn't supplied one. Callers that
	// manage PNI themselves (e.g. account-transfer flows) pass an
	// explicit PNI which we respect — we never overwrite a non-empty
	// value.
	if account.PNI == "" {
		account.PNI = uuid.NewString()
	}

	for i := range account.Devices {
		account.Devices[i].CreatedAt = now
		account.Devices[i].LastSeen = now
		if err := hashDeviceAuthToken(&account.Devices[i]); err != nil {
			return err
		}
	}

	if err := m.store.Create(ctx, account); err != nil {
		return err
	}
	m.publishCreated(account)
	return nil
}

// RecreatePreserving re-creates a previously-deleted account exactly as it
// was, preserving CreatedAt, Version, and the existing hashed device tokens.
// Unlike Create it does not re-initialise those fields. It is used to roll back
// a failed re-registration (or other displacement) so the restored account is
// indistinguishable from the original.
func (m *AccountsManager) RecreatePreserving(ctx context.Context, account *Account) error {
	if account == nil {
		return &InvalidArgumentError{Field: "account", Message: "must not be nil"}
	}
	if account.UUID == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	if err := m.store.Create(ctx, account); err != nil {
		return err
	}
	m.publishCreated(account)
	return nil
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

// GetByPNI retrieves an account by its Phone Number Identity UUID. The PNI
// is a 16-byte UUID generated at account creation and regenerated on phone
// number change.
func (m *AccountsManager) GetByPNI(ctx context.Context, pni string) (*Account, error) {
	if pni == "" {
		return nil, &InvalidArgumentError{Field: "pni", Message: "must not be empty"}
	}
	return m.store.GetByPNI(ctx, pni)
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

	if err := m.store.Update(ctx, account); err != nil {
		return err
	}
	m.publishUpdated(account)
	return nil
}

// Delete removes an account and all of its associated data by UUID.
func (m *AccountsManager) Delete(ctx context.Context, uuid string) error {
	if uuid == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	// Capture the pre-delete state when a bus is attached so the
	// emitted event carries the E164/PNI consumers need for index
	// removal. Skip the read when no bus is configured — callers
	// that don't subscribe don't pay the cost.
	var snapshot *Account
	if m.bus != nil {
		if acc, err := m.store.Get(ctx, uuid); err == nil {
			snapshot = acc
		}
	}
	if err := m.store.Delete(ctx, uuid); err != nil {
		return err
	}
	m.publishDeleted(uuid, snapshot)
	return nil
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

	m.publishUpdated(account)
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

	m.publishUpdated(account)
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

	m.publishUpdated(account)
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

	if err := m.store.Update(ctx, account); err != nil {
		return err
	}
	m.publishUpdated(account)
	return nil
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

	if err := m.store.Update(ctx, account); err != nil {
		return err
	}
	m.publishUpdated(account)
	return nil
}

// ClearGcmRegistration removes the GCM (Android/FCM) push registration token
// from the given device. The read-modify-write is performed inside the manager
// so version handling stays consistent with the other device mutations.
func (m *AccountsManager) ClearGcmRegistration(ctx context.Context, uuid string, deviceID uint64) (*Account, error) {
	return m.clearDevicePush(ctx, uuid, deviceID, func(d *Device) {
		d.GcmRegistrationID = ""
	})
}

// ClearApnRegistration removes the APN (Apple) push registration tokens —
// both the standard and VoIP tokens — from the given device.
func (m *AccountsManager) ClearApnRegistration(ctx context.Context, uuid string, deviceID uint64) (*Account, error) {
	return m.clearDevicePush(ctx, uuid, deviceID, func(d *Device) {
		d.ApnRegistrationID = ""
		d.VoipApnRegistrationID = ""
	})
}

// clearDevicePush applies mutate to the named device, bumps the account
// version, and persists. It centralises the load/mutate/store sequence shared
// by the push-token clearing methods.
func (m *AccountsManager) clearDevicePush(ctx context.Context, uuid string, deviceID uint64, mutate func(*Device)) (*Account, error) {
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

	mutate(device)
	device.LastSeen = time.Now().UTC()
	account.Version++

	if err := m.store.Update(ctx, account); err != nil {
		return nil, err
	}
	m.publishUpdated(account)
	return account, nil
}

// ChangeNumber updates the phone number for the account identified by the given
// UUID. If a PNI identity key is provided, it replaces the existing one. The
// account version is incremented automatically.
//
// If the target number is already owned by a different account, that account is
// deleted first (mirroring the Java Signal-Server behaviour where proving
// ownership of a number via verification displaces the previous holder).
func (m *AccountsManager) ChangeNumber(ctx context.Context, accountUUID, newNumber string, pniIdentityKey []byte) (*Account, error) {
	if accountUUID == "" {
		return nil, &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	if newNumber == "" {
		return nil, &InvalidArgumentError{Field: "number", Message: "must not be empty"}
	}

	account, err := m.store.Get(ctx, accountUUID)
	if err != nil {
		return nil, err
	}

	// If another account owns the target number, it must be displaced. The
	// caller has already proved ownership of the number via verification. The
	// displaced holder shares the target number, so its by-number index entry
	// is the same key the caller is about to claim — we therefore delete the
	// displaced account first, then update the caller. If the update fails we
	// restore the displaced account so a failed number change is not
	// destructive (best-effort compensation in the absence of a KV transaction).
	var displaced *Account
	existing, err := m.store.GetByNumber(ctx, newNumber)
	if err != nil {
		// Only "not found" means the target number is free. Any other error is
		// transient/unknown — proceeding would risk overwriting the real
		// holder's index and orphaning its record, so abort.
		var notFound *AccountNotFoundError
		if !errors.As(err, &notFound) {
			return nil, err
		}
	} else if existing != nil && existing.UUID != accountUUID {
		if delErr := m.store.Delete(ctx, existing.UUID); delErr != nil {
			return nil, delErr
		}
		displaced = existing
	}

	account.Number = newNumber
	// The PNI is bound to the phone number: changing the number invalidates
	// the old Phone Number Identity so that a party who previously knew the
	// account's PNI can no longer address it under the new number. Rotate it
	// to a fresh value (the store removes the stale by-PNI index on Update).
	account.PNI = uuid.NewString()
	if len(pniIdentityKey) > 0 {
		account.PhoneNumberIdentityKey = pniIdentityKey
	}
	account.Version++

	if err := m.store.Update(ctx, account); err != nil {
		if displaced != nil {
			// Restore the displaced account; the update that would have
			// reassigned its number did not commit.
			if restoreErr := m.store.Create(ctx, displaced); restoreErr != nil {
				return nil, &NumberChangeRollbackError{
					DisplacedUUID: displaced.UUID,
					UpdateErr:     err,
					RestoreErr:    restoreErr,
				}
			}
		}
		return nil, err
	}

	if displaced != nil {
		m.publishDeleted(displaced.UUID, displaced)
	}
	m.publishUpdated(account)
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

	if err := m.store.Update(ctx, account); err != nil {
		return err
	}
	m.publishUpdated(account)
	return nil
}

// ListAll streams every account to fn. fn returning an error aborts
// iteration. Used by background workers (account-expiry sweeps,
// orphaned-prekey GC, idle-device sweeps) to scan the full account
// set without leaking the store interface.
func (m *AccountsManager) ListAll(ctx context.Context, fn func(*Account) error) error {
	return m.store.ListAll(ctx, fn)
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
	Name                              string
	GcmRegistrationID                 string
	ApnRegistrationID                 string
	VoipApnRegistrationID             string
	RegistrationID                    *uint32
	PhoneNumberIdentityRegistrationID *uint32
	FetchesMessages                   *bool
	Capabilities                      *DeviceCapabilities
	SignedPreKey                      *SignedPreKey
	KyberPreKey                       *KyberPreKey
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
	if attrs.RegistrationID != nil {
		d.RegistrationID = *attrs.RegistrationID
	}
	if attrs.PhoneNumberIdentityRegistrationID != nil {
		d.PhoneNumberIdentityRegistrationID = *attrs.PhoneNumberIdentityRegistrationID
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
