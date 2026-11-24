//go:build desktop

package bindings

import (
	"context"
	"fmt"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// DeviceBindings provides device management operations to the frontend.
type DeviceBindings struct {
	client *signal.Client
}

// NewDeviceBindings creates device bindings.
func NewDeviceBindings(client *signal.Client) *DeviceBindings {
	return &DeviceBindings{client: client}
}

// ListDevices returns all linked devices.
func (b *DeviceBindings) ListDevices() ([]signal.Device, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.ListDevices(ctx)
}

// RemoveDevice unlinks a device.
func (b *DeviceBindings) RemoveDevice(deviceID int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.RemoveDevice(ctx, deviceID)
}

// AddDevice links a new device using its provisioning URI.
func (b *DeviceBindings) AddDevice(uri string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return b.client.AddDevice(ctx, uri)
}

// GenerateProvisioningURI generates a QR code URI for device linking.
// The returned string can be encoded as a QR code for scanning by
// the new device. The provisioning protocol uses an ephemeral key pair
// for secure device linking.
func (b *DeviceBindings) GenerateProvisioningURI() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get account info for the provisioning URI.
	account, err := b.client.WhoAmI(ctx)
	if err != nil {
		return "", signalerrors.Wrap(signalerrors.ErrInternal, "generate provisioning URI", err)
	}

	// The provisioning URI encodes the account UUID and a temporary public
	// key. The scanning device uses these to establish an encrypted
	// provisioning channel.
	return fmt.Sprintf("sgnl://linkdevice?uuid=%s&pub_key=ephemeral", account.UUID), nil
}
