// Package errors provides typed error definitions for the Signal server.
package errors

// SignalError is the base error type for all Signal server errors.
type SignalError struct {
	Code    ErrorCode
	Message string
	Cause   error
}

// ErrorCode represents a categorized error code.
type ErrorCode int

const (
	// General errors
	ErrInternal ErrorCode = iota
	ErrNotFound
	ErrAlreadyExists
	ErrInvalidArgument
	ErrUnauthenticated
	ErrPermissionDenied
	ErrRateLimited
	ErrUnavailable

	// Account errors
	ErrAccountNotFound
	ErrAccountDisabled
	ErrDeviceLimitExceeded
	ErrRegistrationLocked
	ErrDeviceNotFound

	// Message errors
	ErrMismatchedDevices
	ErrStaleDevices
	ErrMessageTooLarge

	// Key errors
	ErrPreKeyNotAvailable
	ErrPreKeyCountExceeded

	// Profile errors
	ErrProfileNotFound
	ErrProfileVersionConflict
)

func (e *SignalError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *SignalError) Unwrap() error {
	return e.Cause
}

// New creates a new SignalError with the given code and message.
func New(code ErrorCode, message string) *SignalError {
	return &SignalError{Code: code, Message: message}
}

// Wrap creates a new SignalError wrapping an existing error.
func Wrap(code ErrorCode, message string, cause error) *SignalError {
	return &SignalError{Code: code, Message: message, Cause: cause}
}

// Account errors

// AccountNotFoundError indicates the requested account does not exist.
type AccountNotFoundError struct {
	SignalError
}

// NewAccountNotFoundError creates a new AccountNotFoundError.
func NewAccountNotFoundError(message string) *AccountNotFoundError {
	return &AccountNotFoundError{
		SignalError: SignalError{Code: ErrAccountNotFound, Message: message},
	}
}

// DeviceNotFoundError indicates the requested device does not exist.
type DeviceNotFoundError struct {
	SignalError
}

// NewDeviceNotFoundError creates a new DeviceNotFoundError.
func NewDeviceNotFoundError(message string) *DeviceNotFoundError {
	return &DeviceNotFoundError{
		SignalError: SignalError{Code: ErrDeviceNotFound, Message: message},
	}
}

// DeviceLimitExceededError indicates too many devices are linked to an account.
type DeviceLimitExceededError struct {
	SignalError
	MaxDevices int
	Current    int
}

// NewDeviceLimitExceededError creates a new DeviceLimitExceededError.
func NewDeviceLimitExceededError(max, current int) *DeviceLimitExceededError {
	return &DeviceLimitExceededError{
		SignalError: SignalError{Code: ErrDeviceLimitExceeded, Message: "device limit exceeded"},
		MaxDevices:  max,
		Current:     current,
	}
}

// RateLimitedError indicates a rate limit has been exceeded.
type RateLimitedError struct {
	SignalError
	RetryAfterSeconds int64
}

// NewRateLimitedError creates a new RateLimitedError.
func NewRateLimitedError(retryAfter int64) *RateLimitedError {
	return &RateLimitedError{
		SignalError:       SignalError{Code: ErrRateLimited, Message: "rate limit exceeded"},
		RetryAfterSeconds: retryAfter,
	}
}

// MismatchedDevicesError indicates message was sent to wrong set of devices.
type MismatchedDevicesError struct {
	SignalError
	MissingDevices []uint64
	ExtraDevices   []uint64
}

// NewMismatchedDevicesError creates a new MismatchedDevicesError.
func NewMismatchedDevicesError(missing, extra []uint64) *MismatchedDevicesError {
	return &MismatchedDevicesError{
		SignalError:    SignalError{Code: ErrMismatchedDevices, Message: "mismatched devices"},
		MissingDevices: missing,
		ExtraDevices:   extra,
	}
}

// StaleDevicesError indicates message references stale device registrations.
type StaleDevicesError struct {
	SignalError
	StaleDevices []uint64
}

// NewStaleDevicesError creates a new StaleDevicesError.
func NewStaleDevicesError(stale []uint64) *StaleDevicesError {
	return &StaleDevicesError{
		SignalError:  SignalError{Code: ErrStaleDevices, Message: "stale devices"},
		StaleDevices: stale,
	}
}

// RegistrationLockedError indicates that an account cannot be re-registered
// because it has an active registration lock. The client must supply the
// correct PIN before registration can proceed.
type RegistrationLockedError struct {
	SignalError
	// TimeRemaining is the duration in seconds for which the registration lock
	// remains active. Clients should display this to the user.
	TimeRemaining int64
}

// NewRegistrationLockedError creates a new RegistrationLockedError with the
// given remaining lock duration in seconds.
func NewRegistrationLockedError(timeRemaining int64) *RegistrationLockedError {
	return &RegistrationLockedError{
		SignalError:   SignalError{Code: ErrRegistrationLocked, Message: "registration locked"},
		TimeRemaining: timeRemaining,
	}
}
