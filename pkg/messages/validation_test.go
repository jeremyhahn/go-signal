package messages

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/auth"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// --------------------------------------------------------------------------
// helpers
// --------------------------------------------------------------------------

// testSaltedHash is a non-nil *auth.SaltedTokenHash used to satisfy the
// IsDeviceEnabled check (requires AuthTokenHash != nil && SignedPreKey != nil).
var testSaltedHash = &auth.SaltedTokenHash{
	Salt: "00000000000000000000000000000000",
	Hash: "0000000000000000000000000000000000000000000000000000000000000000",
}

// enabledDevice builds a fully-enabled Device with the given ID and
// registration ID. IsDeviceEnabled requires a non-nil SignedPreKey and a
// non-nil AuthTokenHash.
func enabledDevice(id uint64, registrationID uint32) accounts.Device {
	return accounts.Device{
		ID:             id,
		AuthTokenHash:  testSaltedHash,
		RegistrationID: registrationID,
		SignedPreKey: &accounts.SignedPreKey{
			KeyID:     1,
			PublicKey: []byte("pub"),
			Signature: []byte("sig"),
		},
	}
}

// disabledDevice builds a device that IsDeviceEnabled returns false for
// (no AuthTokenHash, no signed pre-key).
func disabledDevice(id uint64) accounts.Device {
	return accounts.Device{ID: id}
}

// accountWith builds an Account whose Devices slice is the provided list.
func accountWith(devices ...accounts.Device) *accounts.Account {
	return &accounts.Account{Devices: devices}
}

// --------------------------------------------------------------------------
// ValidateDeviceSet
// --------------------------------------------------------------------------

func TestValidateDeviceSet_SingleDeviceExact(t *testing.T) {
	acct := accountWith(enabledDevice(1, 111))
	msgs := []DeviceMessage{{DestinationDeviceID: 1}}

	if err := ValidateDeviceSet(acct, msgs); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidateDeviceSet_MultipleDevicesAllAddressed(t *testing.T) {
	acct := accountWith(
		enabledDevice(1, 111),
		enabledDevice(2, 222),
		enabledDevice(3, 333),
	)
	msgs := []DeviceMessage{
		{DestinationDeviceID: 1},
		{DestinationDeviceID: 2},
		{DestinationDeviceID: 3},
	}

	if err := ValidateDeviceSet(acct, msgs); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidateDeviceSet_MissingDevice_Returns409(t *testing.T) {
	acct := accountWith(
		enabledDevice(1, 111),
		enabledDevice(2, 222),
	)
	// Sender only addressed device 1; device 2 is missing.
	msgs := []DeviceMessage{{DestinationDeviceID: 1}}

	err := ValidateDeviceSet(acct, msgs)
	if err == nil {
		t.Fatal("expected MismatchedDevicesError, got nil")
	}

	var mismatch *signalerrors.MismatchedDevicesError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected *MismatchedDevicesError, got %T", err)
	}
	if len(mismatch.MissingDevices) != 1 || mismatch.MissingDevices[0] != 2 {
		t.Errorf("expected missingDevices=[2], got %v", mismatch.MissingDevices)
	}
	if len(mismatch.ExtraDevices) != 0 {
		t.Errorf("expected no extraDevices, got %v", mismatch.ExtraDevices)
	}
}

func TestValidateDeviceSet_ExtraDevice_Returns409(t *testing.T) {
	acct := accountWith(enabledDevice(1, 111))
	// Sender addressed device 1 and a non-existent device 99.
	msgs := []DeviceMessage{
		{DestinationDeviceID: 1},
		{DestinationDeviceID: 99},
	}

	err := ValidateDeviceSet(acct, msgs)
	if err == nil {
		t.Fatal("expected MismatchedDevicesError, got nil")
	}

	var mismatch *signalerrors.MismatchedDevicesError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected *MismatchedDevicesError, got %T", err)
	}
	if len(mismatch.ExtraDevices) != 1 || mismatch.ExtraDevices[0] != 99 {
		t.Errorf("expected extraDevices=[99], got %v", mismatch.ExtraDevices)
	}
	if len(mismatch.MissingDevices) != 0 {
		t.Errorf("expected no missingDevices, got %v", mismatch.MissingDevices)
	}
}

func TestValidateDeviceSet_BothMissingAndExtra(t *testing.T) {
	acct := accountWith(
		enabledDevice(1, 111),
		enabledDevice(2, 222),
	)
	// Sender addressed 1 and 99 (extra), but missed 2 (missing).
	msgs := []DeviceMessage{
		{DestinationDeviceID: 1},
		{DestinationDeviceID: 99},
	}

	err := ValidateDeviceSet(acct, msgs)
	if err == nil {
		t.Fatal("expected MismatchedDevicesError, got nil")
	}

	var mismatch *signalerrors.MismatchedDevicesError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected *MismatchedDevicesError, got %T", err)
	}
	if len(mismatch.MissingDevices) != 1 {
		t.Errorf("expected 1 missingDevice, got %v", mismatch.MissingDevices)
	}
	if len(mismatch.ExtraDevices) != 1 {
		t.Errorf("expected 1 extraDevice, got %v", mismatch.ExtraDevices)
	}
}

func TestValidateDeviceSet_DisabledDeviceIgnored(t *testing.T) {
	// Device 2 is disabled; the sender only needs to address device 1.
	acct := accountWith(
		enabledDevice(1, 111),
		disabledDevice(2),
	)
	msgs := []DeviceMessage{{DestinationDeviceID: 1}}

	if err := ValidateDeviceSet(acct, msgs); err != nil {
		t.Fatalf("expected nil (disabled device should be ignored), got %v", err)
	}
}

func TestValidateDeviceSet_EmptyMessageList_AllDevicesMissing(t *testing.T) {
	acct := accountWith(enabledDevice(1, 111))
	msgs := []DeviceMessage{}

	err := ValidateDeviceSet(acct, msgs)
	if err == nil {
		t.Fatal("expected MismatchedDevicesError for empty message list")
	}

	var mismatch *signalerrors.MismatchedDevicesError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected *MismatchedDevicesError, got %T", err)
	}
	if len(mismatch.MissingDevices) == 0 {
		t.Error("expected at least one missing device")
	}
}

func TestValidateDeviceSet_AccountNoEnabledDevices(t *testing.T) {
	// Account has no enabled devices; any addressed device is "extra".
	acct := accountWith(disabledDevice(1))
	msgs := []DeviceMessage{{DestinationDeviceID: 1}}

	err := ValidateDeviceSet(acct, msgs)
	if err == nil {
		t.Fatal("expected MismatchedDevicesError")
	}

	var mismatch *signalerrors.MismatchedDevicesError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected *MismatchedDevicesError, got %T", err)
	}
	if len(mismatch.ExtraDevices) == 0 {
		t.Error("expected at least one extra device")
	}
}

// --------------------------------------------------------------------------
// ValidateRegistrationIDs
// --------------------------------------------------------------------------

func TestValidateRegistrationIDs_AllMatch(t *testing.T) {
	acct := accountWith(enabledDevice(1, 111))
	msgs := []DeviceMessage{{DestinationDeviceID: 1, RegistrationID: 111}}

	if err := ValidateRegistrationIDs(acct, msgs); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidateRegistrationIDs_MultipleDevicesAllMatch(t *testing.T) {
	acct := accountWith(
		enabledDevice(1, 111),
		enabledDevice(2, 222),
	)
	msgs := []DeviceMessage{
		{DestinationDeviceID: 1, RegistrationID: 111},
		{DestinationDeviceID: 2, RegistrationID: 222},
	}

	if err := ValidateRegistrationIDs(acct, msgs); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidateRegistrationIDs_StaleRegistrationID_Returns410(t *testing.T) {
	acct := accountWith(enabledDevice(1, 111))
	// Sender has an outdated registration ID of 999 for device 1.
	msgs := []DeviceMessage{{DestinationDeviceID: 1, RegistrationID: 999}}

	err := ValidateRegistrationIDs(acct, msgs)
	if err == nil {
		t.Fatal("expected StaleDevicesError, got nil")
	}

	var stale *signalerrors.StaleDevicesError
	if !errors.As(err, &stale) {
		t.Fatalf("expected *StaleDevicesError, got %T", err)
	}
	if len(stale.StaleDevices) != 1 || stale.StaleDevices[0] != 1 {
		t.Errorf("expected staleDevices=[1], got %v", stale.StaleDevices)
	}
}

func TestValidateRegistrationIDs_MultipleStaleDevices(t *testing.T) {
	acct := accountWith(
		enabledDevice(1, 111),
		enabledDevice(2, 222),
		enabledDevice(3, 333),
	)
	msgs := []DeviceMessage{
		{DestinationDeviceID: 1, RegistrationID: 111}, // current
		{DestinationDeviceID: 2, RegistrationID: 999}, // stale
		{DestinationDeviceID: 3, RegistrationID: 888}, // stale
	}

	err := ValidateRegistrationIDs(acct, msgs)
	if err == nil {
		t.Fatal("expected StaleDevicesError, got nil")
	}

	var stale *signalerrors.StaleDevicesError
	if !errors.As(err, &stale) {
		t.Fatalf("expected *StaleDevicesError, got %T", err)
	}
	if len(stale.StaleDevices) != 2 {
		t.Errorf("expected 2 stale devices, got %v", stale.StaleDevices)
	}
}

func TestValidateRegistrationIDs_ZeroRegistrationIDSkipped(t *testing.T) {
	acct := accountWith(enabledDevice(1, 111))
	// RegistrationID == 0 means sender did not provide one; must be skipped.
	msgs := []DeviceMessage{{DestinationDeviceID: 1, RegistrationID: 0}}

	if err := ValidateRegistrationIDs(acct, msgs); err != nil {
		t.Fatalf("expected nil when registration ID is 0, got %v", err)
	}
}

func TestValidateRegistrationIDs_UnknownDeviceSkipped(t *testing.T) {
	// Device 99 does not exist; ValidateDeviceSet would catch it.
	// ValidateRegistrationIDs should simply skip it.
	acct := accountWith(enabledDevice(1, 111))
	msgs := []DeviceMessage{
		{DestinationDeviceID: 1, RegistrationID: 111},
		{DestinationDeviceID: 99, RegistrationID: 777},
	}

	if err := ValidateRegistrationIDs(acct, msgs); err != nil {
		t.Fatalf("expected nil (unknown device skipped), got %v", err)
	}
}

func TestValidateRegistrationIDs_EmptyMessageList(t *testing.T) {
	acct := accountWith(enabledDevice(1, 111))
	if err := ValidateRegistrationIDs(acct, []DeviceMessage{}); err != nil {
		t.Fatalf("expected nil for empty message list, got %v", err)
	}
}

// --------------------------------------------------------------------------
// DeviceMessage type
// --------------------------------------------------------------------------

func TestDeviceMessage_ZeroValue(t *testing.T) {
	var dm DeviceMessage
	if dm.DestinationDeviceID != 0 {
		t.Errorf("expected zero DestinationDeviceID, got %d", dm.DestinationDeviceID)
	}
	if dm.RegistrationID != 0 {
		t.Errorf("expected zero RegistrationID, got %d", dm.RegistrationID)
	}
}

func TestDeviceMessage_FieldAssignment(t *testing.T) {
	dm := DeviceMessage{DestinationDeviceID: 42, RegistrationID: 9999}
	if dm.DestinationDeviceID != 42 {
		t.Errorf("expected 42, got %d", dm.DestinationDeviceID)
	}
	if dm.RegistrationID != 9999 {
		t.Errorf("expected 9999, got %d", dm.RegistrationID)
	}
}
