package accounts

import "strconv"

// AccountNotFoundError indicates the requested account does not exist.
type AccountNotFoundError struct {
	Identifier string
}

func (e *AccountNotFoundError) Error() string {
	return "account not found: " + e.Identifier
}

// AccountAlreadyExistsError indicates an account with the same UUID or phone
// number already exists.
type AccountAlreadyExistsError struct {
	Identifier string
}

func (e *AccountAlreadyExistsError) Error() string {
	return "account already exists: " + e.Identifier
}

// DeviceNotFoundError indicates the requested device does not exist on the
// account.
type DeviceNotFoundError struct {
	AccountUUID string
	DeviceID    uint64
}

func (e *DeviceNotFoundError) Error() string {
	return "device " + strconv.FormatUint(e.DeviceID, 10) + " not found on account " + e.AccountUUID
}

// DeviceLimitExceededError indicates the account has reached the maximum
// number of linked devices.
type DeviceLimitExceededError struct {
	MaxDevices int
	Current    int
}

func (e *DeviceLimitExceededError) Error() string {
	return "device limit exceeded: " + strconv.Itoa(e.Current) + " of " + strconv.Itoa(e.MaxDevices) + " allowed"
}

// VersionConflictError indicates an optimistic locking conflict during an
// account update.
type VersionConflictError struct {
	AccountUUID     string
	ExpectedVersion uint64
	ActualVersion   uint64
}

func (e *VersionConflictError) Error() string {
	return "version conflict for account " + e.AccountUUID +
		": expected " + strconv.FormatUint(e.ExpectedVersion, 10) +
		", got " + strconv.FormatUint(e.ActualVersion, 10)
}

// InvalidArgumentError indicates that a required argument was missing or
// invalid.
type InvalidArgumentError struct {
	Field   string
	Message string
}

func (e *InvalidArgumentError) Error() string {
	return "invalid argument: " + e.Field + ": " + e.Message
}

// PrimaryDeviceRemovalError indicates an attempt to remove the primary device
// from an account.
type PrimaryDeviceRemovalError struct {
	AccountUUID string
}

func (e *PrimaryDeviceRemovalError) Error() string {
	return "cannot remove primary device from account " + e.AccountUUID
}

// RegistrationLockError indicates a failure while setting the registration
// lock on an account (e.g., failure to generate a random salt).
type RegistrationLockError struct {
	AccountUUID string
	Cause       error
}

func (e *RegistrationLockError) Error() string {
	return "registration lock error for account " + e.AccountUUID + ": " + e.Cause.Error()
}

func (e *RegistrationLockError) Unwrap() error {
	return e.Cause
}
