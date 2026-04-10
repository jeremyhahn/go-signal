// Package service provides the service layer abstraction that sits between
// the protocol handlers (REST, gRPC) and the domain managers. Each service
// interface expresses the operations a transport handler needs; concrete
// implementations delegate to the underlying managers.
package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// AccountService defines the account operations exposed to protocol handlers.
// All methods accept a context for cancellation and deadline propagation.
type AccountService interface {
	// Create registers a new account and returns the created record.
	Create(ctx context.Context, account *accounts.Account) error

	// Get retrieves an account by its UUID.
	Get(ctx context.Context, uuid string) (*accounts.Account, error)

	// GetByNumber retrieves an account by its E.164 phone number.
	GetByNumber(ctx context.Context, number string) (*accounts.Account, error)

	// Update persists mutations to an existing account. The account version
	// is incremented automatically by the underlying manager.
	Update(ctx context.Context, account *accounts.Account) error

	// Delete removes an account and all associated data.
	Delete(ctx context.Context, uuid string) error

	// SetRegistrationLock hashes pin and stores it on the account.
	SetRegistrationLock(ctx context.Context, uuid string, pin string) error

	// ClearRegistrationLock removes the registration lock from an account.
	ClearRegistrationLock(ctx context.Context, uuid string) error

	// SetDeviceAttributes updates mutable attributes on a specific device.
	SetDeviceAttributes(ctx context.Context, uuid string, deviceID uint64, attrs accounts.DeviceAttributes) (*accounts.Account, error)

	// AddDevice links a new device to the account.
	AddDevice(ctx context.Context, uuid string, device *accounts.Device) (*accounts.Account, error)

	// RemoveDevice unlinks a device from the account.
	RemoveDevice(ctx context.Context, uuid string, deviceID uint64) (*accounts.Account, error)

	// ChangeNumber updates the E.164 number for an account.
	ChangeNumber(ctx context.Context, uuid string, number string, pniIdentityKey []byte) (*accounts.Account, error)

	// SetPhoneNumberDiscoverability controls whether the account is
	// discoverable via phone number lookup.
	SetPhoneNumberDiscoverability(ctx context.Context, uuid string, discoverable bool) error

	// GetDataReport returns a regulatory data summary for an account.
	GetDataReport(ctx context.Context, uuid string) (*accounts.DataReport, error)
}

// accountService is the default AccountService backed by an AccountsManager.
type accountService struct {
	manager *accounts.AccountsManager
}

// NewAccountService returns an AccountService that delegates to the given
// AccountsManager. The manager must not be nil.
func NewAccountService(manager *accounts.AccountsManager) AccountService {
	return &accountService{manager: manager}
}

func (s *accountService) Create(ctx context.Context, account *accounts.Account) error {
	return s.manager.Create(ctx, account)
}

func (s *accountService) Get(ctx context.Context, uuid string) (*accounts.Account, error) {
	return s.manager.Get(ctx, uuid)
}

func (s *accountService) GetByNumber(ctx context.Context, number string) (*accounts.Account, error) {
	return s.manager.GetByNumber(ctx, number)
}

func (s *accountService) Update(ctx context.Context, account *accounts.Account) error {
	return s.manager.Update(ctx, account)
}

func (s *accountService) Delete(ctx context.Context, uuid string) error {
	return s.manager.Delete(ctx, uuid)
}

func (s *accountService) SetRegistrationLock(ctx context.Context, uuid string, pin string) error {
	return s.manager.SetRegistrationLock(ctx, uuid, pin)
}

func (s *accountService) ClearRegistrationLock(ctx context.Context, uuid string) error {
	return s.manager.ClearRegistrationLock(ctx, uuid)
}

func (s *accountService) SetDeviceAttributes(ctx context.Context, uuid string, deviceID uint64, attrs accounts.DeviceAttributes) (*accounts.Account, error) {
	return s.manager.SetDeviceAttributes(ctx, uuid, deviceID, attrs)
}

func (s *accountService) AddDevice(ctx context.Context, uuid string, device *accounts.Device) (*accounts.Account, error) {
	return s.manager.AddDevice(ctx, uuid, device)
}

func (s *accountService) RemoveDevice(ctx context.Context, uuid string, deviceID uint64) (*accounts.Account, error) {
	return s.manager.RemoveDevice(ctx, uuid, deviceID)
}

func (s *accountService) ChangeNumber(ctx context.Context, uuid string, number string, pniIdentityKey []byte) (*accounts.Account, error) {
	return s.manager.ChangeNumber(ctx, uuid, number, pniIdentityKey)
}

func (s *accountService) SetPhoneNumberDiscoverability(ctx context.Context, uuid string, discoverable bool) error {
	return s.manager.SetPhoneNumberDiscoverability(ctx, uuid, discoverable)
}

func (s *accountService) GetDataReport(ctx context.Context, uuid string) (*accounts.DataReport, error) {
	return s.manager.GetDataReport(ctx, uuid)
}
