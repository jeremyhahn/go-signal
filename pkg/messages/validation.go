package messages

import (
	"github.com/jeremyhahn/go-signal/pkg/accounts"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// DeviceMessage carries the minimal fields needed from an incoming message
// entry to perform device-set and registration-ID validation.
type DeviceMessage struct {
	// DestinationDeviceID is the device this message is addressed to.
	DestinationDeviceID uint64
	// RegistrationID is the sender's last-known registration ID for that device.
	// A value of zero means the sender did not supply a registration ID, in
	// which case stale-device validation is skipped for this entry.
	RegistrationID uint32
}

// ValidateDeviceSet returns *signalerrors.MismatchedDevicesError unless the addressed devices exactly match the enabled ones.
func ValidateDeviceSet(recipient *accounts.Account, messages []DeviceMessage) error {
	// Build the set of device IDs the sender addressed.
	sent := make(map[uint64]struct{}, len(messages))
	for i := range messages {
		sent[messages[i].DestinationDeviceID] = struct{}{}
	}

	// Build the set of enabled device IDs the recipient actually has.
	actual := make(map[uint64]struct{}, len(recipient.Devices))
	for i := range recipient.Devices {
		if accounts.IsDeviceEnabled(&recipient.Devices[i]) {
			actual[recipient.Devices[i].ID] = struct{}{}
		}
	}

	var missingDevices []uint64
	for id := range actual {
		if _, ok := sent[id]; !ok {
			missingDevices = append(missingDevices, id)
		}
	}

	var extraDevices []uint64
	for id := range sent {
		if _, ok := actual[id]; !ok {
			extraDevices = append(extraDevices, id)
		}
	}

	if len(missingDevices) > 0 || len(extraDevices) > 0 {
		return signalerrors.NewMismatchedDevicesError(missingDevices, extraDevices)
	}

	return nil
}

// ValidateRegistrationIDs returns *signalerrors.StaleDevicesError for addressed devices whose registration ID differs; zero IDs are skipped.
func ValidateRegistrationIDs(recipient *accounts.Account, messages []DeviceMessage) error {
	var staleDevices []uint64

	for i := range messages {
		if messages[i].RegistrationID == 0 {
			// Sender did not supply a registration ID; skip this device.
			continue
		}

		device := recipient.GetDevice(messages[i].DestinationDeviceID)
		if device == nil {
			// Device does not exist; this is caught by ValidateDeviceSet.
			continue
		}

		if device.RegistrationID != messages[i].RegistrationID {
			staleDevices = append(staleDevices, messages[i].DestinationDeviceID)
		}
	}

	if len(staleDevices) > 0 {
		return signalerrors.NewStaleDevicesError(staleDevices)
	}

	return nil
}
