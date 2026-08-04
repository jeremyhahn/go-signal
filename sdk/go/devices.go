package signal

import (
	"context"
	"fmt"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// ListDevices returns all devices linked to the authenticated account.
func (c *Client) ListDevices(ctx context.Context) ([]Device, error) {
	var result struct {
		Devices []Device `json:"devices"`
	}
	if err := c.doRequest(ctx, "GET", "/v1/devices", nil, &result); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "list devices", err)
	}
	return result.Devices, nil
}

// RemoveDevice removes a linked device.
func (c *Client) RemoveDevice(ctx context.Context, deviceID int) error {
	path := fmt.Sprintf("/v1/devices/%d", deviceID)
	return c.doRequest(ctx, "DELETE", path, nil, nil)
}

// AddDevice links a new device via provisioning URI. The URI contains an
// ephemeral public key and UUID used to establish a secure provisioning channel.
func (c *Client) AddDevice(ctx context.Context, uri string) error {
	return c.doRequest(ctx, "PUT", "/v1/provisioning/"+uri, nil, nil)
}
