package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/devices"
)

// DeviceService defines the device-provisioning operations exposed to protocol
// handlers.
type DeviceService interface {
	// CreateProvisioningCode generates a time-limited provisioning code for
	// the given account UUID.
	CreateProvisioningCode(ctx context.Context, accountUUID string) (*devices.ProvisioningCode, error)

	// LinkDevice validates a provisioning code and attaches the new device
	// to the associated account.
	LinkDevice(ctx context.Context, code string, req *devices.LinkDeviceRequest) (*devices.LinkDeviceResponse, error)

	// SetCapabilities updates the capability set of a specific device.
	SetCapabilities(ctx context.Context, accountUUID string, deviceID uint64, caps map[string]bool) error
}

// deviceService is the default DeviceService backed by a DevicesManager.
type deviceService struct {
	manager *devices.DevicesManager
}

// NewDeviceService returns a DeviceService that delegates to the given
// DevicesManager. The manager must not be nil.
func NewDeviceService(manager *devices.DevicesManager) DeviceService {
	return &deviceService{manager: manager}
}

func (s *deviceService) CreateProvisioningCode(ctx context.Context, accountUUID string) (*devices.ProvisioningCode, error) {
	return s.manager.CreateProvisioningCode(ctx, accountUUID)
}

func (s *deviceService) LinkDevice(ctx context.Context, code string, req *devices.LinkDeviceRequest) (*devices.LinkDeviceResponse, error) {
	return s.manager.LinkDevice(ctx, code, req)
}

func (s *deviceService) SetCapabilities(ctx context.Context, accountUUID string, deviceID uint64, caps map[string]bool) error {
	return s.manager.SetCapabilities(ctx, accountUUID, deviceID, caps)
}
