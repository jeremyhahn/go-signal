package accounts

import (
	"errors"
	"testing"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

func TestAccountNotFoundError_Error(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		want       string
	}{
		{
			name:       "with identifier",
			identifier: "abc-123",
			want:       "account not found: abc-123",
		},
		{
			name:       "empty identifier",
			identifier: "",
			want:       "account not found: ",
		},
		{
			name:       "uuid identifier",
			identifier: "550e8400-e29b-41d4-a716-446655440000",
			want:       "account not found: 550e8400-e29b-41d4-a716-446655440000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &AccountNotFoundError{Identifier: tt.identifier}
			got := e.Error()
			if got != tt.want {
				t.Errorf("AccountNotFoundError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAccountNotFoundError_TypeAssertion(t *testing.T) {
	var err error = &AccountNotFoundError{Identifier: "test-uuid"}

	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Fatal("expected errors.As to succeed for *AccountNotFoundError")
	}
	if target.Identifier != "test-uuid" {
		t.Errorf("Identifier = %q, want %q", target.Identifier, "test-uuid")
	}
}

func TestAccountAlreadyExistsError_Error(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		want       string
	}{
		{
			name:       "with identifier",
			identifier: "user-uuid-1",
			want:       "account already exists: user-uuid-1",
		},
		{
			name:       "empty identifier",
			identifier: "",
			want:       "account already exists: ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &AccountAlreadyExistsError{Identifier: tt.identifier}
			got := e.Error()
			if got != tt.want {
				t.Errorf("AccountAlreadyExistsError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAccountAlreadyExistsError_TypeAssertion(t *testing.T) {
	var err error = &AccountAlreadyExistsError{Identifier: "+15551234567"}

	var target *AccountAlreadyExistsError
	if !errors.As(err, &target) {
		t.Fatal("expected errors.As to succeed for *AccountAlreadyExistsError")
	}
	if target.Identifier != "+15551234567" {
		t.Errorf("Identifier = %q, want %q", target.Identifier, "+15551234567")
	}
}

func TestDeviceNotFoundError_Error(t *testing.T) {
	tests := []struct {
		name        string
		accountUUID string
		deviceID    uint64
		want        string
	}{
		{
			name:        "standard device",
			accountUUID: "abc-123",
			deviceID:    2,
			want:        "device 2 not found on account abc-123",
		},
		{
			name:        "large device ID",
			accountUUID: "xyz-789",
			deviceID:    18446744073709551615,
			want:        "device 18446744073709551615 not found on account xyz-789",
		},
		{
			name:        "zero device ID",
			accountUUID: "test",
			deviceID:    0,
			want:        "device 0 not found on account test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &DeviceNotFoundError{AccountUUID: tt.accountUUID, DeviceID: tt.deviceID}
			got := e.Error()
			if got != tt.want {
				t.Errorf("DeviceNotFoundError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDeviceNotFoundError_TypeAssertion(t *testing.T) {
	var err error = &DeviceNotFoundError{AccountUUID: "acc-1", DeviceID: 5}

	var target *DeviceNotFoundError
	if !errors.As(err, &target) {
		t.Fatal("expected errors.As to succeed for *DeviceNotFoundError")
	}
	if target.AccountUUID != "acc-1" || target.DeviceID != 5 {
		t.Errorf("unexpected fields: AccountUUID=%q, DeviceID=%d", target.AccountUUID, target.DeviceID)
	}
}

func TestDeviceLimitExceededError_Error(t *testing.T) {
	tests := []struct {
		name       string
		maxDevices int
		current    int
		want       string
	}{
		{
			name:       "at default limit",
			maxDevices: 6,
			current:    6,
			want:       "device limit exceeded: 6 of 6 allowed",
		},
		{
			name:       "custom limit",
			maxDevices: 10,
			current:    10,
			want:       "device limit exceeded: 10 of 10 allowed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &DeviceLimitExceededError{MaxDevices: tt.maxDevices, Current: tt.current}
			got := e.Error()
			if got != tt.want {
				t.Errorf("DeviceLimitExceededError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDeviceLimitExceededError_TypeAssertion(t *testing.T) {
	var err error = &DeviceLimitExceededError{MaxDevices: 6, Current: 6}

	var target *DeviceLimitExceededError
	if !errors.As(err, &target) {
		t.Fatal("expected errors.As to succeed for *DeviceLimitExceededError")
	}
	if target.MaxDevices != 6 || target.Current != 6 {
		t.Errorf("unexpected fields: MaxDevices=%d, Current=%d", target.MaxDevices, target.Current)
	}
}

func TestVersionConflictError_Error(t *testing.T) {
	tests := []struct {
		name            string
		accountUUID     string
		expectedVersion uint64
		actualVersion   uint64
		want            string
	}{
		{
			name:            "simple conflict",
			accountUUID:     "uuid-1",
			expectedVersion: 1,
			actualVersion:   2,
			want:            "version conflict for account uuid-1: expected 1, got 2",
		},
		{
			name:            "large versions",
			accountUUID:     "uuid-2",
			expectedVersion: 1000,
			actualVersion:   999,
			want:            "version conflict for account uuid-2: expected 1000, got 999",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &VersionConflictError{
				AccountUUID:     tt.accountUUID,
				ExpectedVersion: tt.expectedVersion,
				ActualVersion:   tt.actualVersion,
			}
			got := e.Error()
			if got != tt.want {
				t.Errorf("VersionConflictError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVersionConflictError_TypeAssertion(t *testing.T) {
	var err error = &VersionConflictError{AccountUUID: "u", ExpectedVersion: 3, ActualVersion: 5}

	var target *VersionConflictError
	if !errors.As(err, &target) {
		t.Fatal("expected errors.As to succeed for *VersionConflictError")
	}
	if target.ExpectedVersion != 3 || target.ActualVersion != 5 {
		t.Errorf("unexpected fields: Expected=%d, Actual=%d", target.ExpectedVersion, target.ActualVersion)
	}
}

func TestInvalidArgumentError_Error(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		message string
		want    string
	}{
		{
			name:    "uuid field",
			field:   "uuid",
			message: "must not be empty",
			want:    "invalid argument: uuid: must not be empty",
		},
		{
			name:    "empty field name",
			field:   "",
			message: "something wrong",
			want:    "invalid argument: : something wrong",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &InvalidArgumentError{Field: tt.field, Message: tt.message}
			got := e.Error()
			if got != tt.want {
				t.Errorf("InvalidArgumentError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInvalidArgumentError_TypeAssertion(t *testing.T) {
	var err error = &InvalidArgumentError{Field: "pin", Message: "too short"}

	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatal("expected errors.As to succeed for *InvalidArgumentError")
	}
	if target.Field != "pin" || target.Message != "too short" {
		t.Errorf("unexpected fields: Field=%q, Message=%q", target.Field, target.Message)
	}
}

func TestPrimaryDeviceRemovalError_Error(t *testing.T) {
	tests := []struct {
		name        string
		accountUUID string
		want        string
	}{
		{
			name:        "standard uuid",
			accountUUID: "uuid-abc",
			want:        "cannot remove primary device from account uuid-abc",
		},
		{
			name:        "empty uuid",
			accountUUID: "",
			want:        "cannot remove primary device from account ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &PrimaryDeviceRemovalError{AccountUUID: tt.accountUUID}
			got := e.Error()
			if got != tt.want {
				t.Errorf("PrimaryDeviceRemovalError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPrimaryDeviceRemovalError_TypeAssertion(t *testing.T) {
	var err error = &PrimaryDeviceRemovalError{AccountUUID: "acc-42"}

	var target *PrimaryDeviceRemovalError
	if !errors.As(err, &target) {
		t.Fatal("expected errors.As to succeed for *PrimaryDeviceRemovalError")
	}
	if target.AccountUUID != "acc-42" {
		t.Errorf("AccountUUID = %q, want %q", target.AccountUUID, "acc-42")
	}
}

func TestRegistrationLockError_Error(t *testing.T) {
	tests := []struct {
		name        string
		accountUUID string
		cause       error
		want        string
	}{
		{
			name:        "with cause",
			accountUUID: "uuid-rl",
			cause:       errors.New("entropy exhausted"),
			want:        "registration lock error for account uuid-rl: entropy exhausted",
		},
		{
			name:        "nested error",
			accountUUID: "uuid-nested",
			cause:       signalerrors.Wrap(signalerrors.ErrInternal, "inner", errors.New("root cause")),
			want:        "registration lock error for account uuid-nested: inner: root cause",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &RegistrationLockError{AccountUUID: tt.accountUUID, Cause: tt.cause}
			got := e.Error()
			if got != tt.want {
				t.Errorf("RegistrationLockError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRegistrationLockError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	e := &RegistrationLockError{AccountUUID: "uuid-1", Cause: cause}

	unwrapped := e.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap() returned %v, want %v", unwrapped, cause)
	}
}

func TestRegistrationLockError_ErrorsIs(t *testing.T) {
	root := errors.New("root")
	wrapped := signalerrors.Wrap(signalerrors.ErrInternal, "mid", root)
	e := &RegistrationLockError{AccountUUID: "u", Cause: wrapped}

	if !errors.Is(e, root) {
		t.Error("expected errors.Is to find root cause through Unwrap chain")
	}
}

func TestRegistrationLockError_TypeAssertion(t *testing.T) {
	var err error = &RegistrationLockError{AccountUUID: "acc-rl", Cause: errors.New("fail")}

	var target *RegistrationLockError
	if !errors.As(err, &target) {
		t.Fatal("expected errors.As to succeed for *RegistrationLockError")
	}
	if target.AccountUUID != "acc-rl" {
		t.Errorf("AccountUUID = %q, want %q", target.AccountUUID, "acc-rl")
	}
}

// --- NumberChangeRollbackError ---

func TestNumberChangeRollbackError_Error(t *testing.T) {
	tests := []struct {
		name          string
		displacedUUID string
		updateErr     error
		restoreErr    error
		want          string
	}{
		{
			name:          "both errors populated",
			displacedUUID: "uuid-displaced",
			updateErr:     errors.New("update failed"),
			restoreErr:    errors.New("restore failed"),
			want:          "number change failed and displaced account uuid-displaced could not be restored: update error: update failed; restore error: restore failed",
		},
		{
			name:          "empty displaced uuid",
			displacedUUID: "",
			updateErr:     errors.New("update err"),
			restoreErr:    errors.New("restore err"),
			want:          "number change failed and displaced account  could not be restored: update error: update err; restore error: restore err",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &NumberChangeRollbackError{
				DisplacedUUID: tt.displacedUUID,
				UpdateErr:     tt.updateErr,
				RestoreErr:    tt.restoreErr,
			}
			got := e.Error()
			if got != tt.want {
				t.Errorf("NumberChangeRollbackError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNumberChangeRollbackError_Unwrap(t *testing.T) {
	updateErr := errors.New("the update error")
	e := &NumberChangeRollbackError{
		DisplacedUUID: "uuid-1",
		UpdateErr:     updateErr,
		RestoreErr:    errors.New("restore err"),
	}
	if got := e.Unwrap(); got != updateErr {
		t.Errorf("Unwrap() = %v, want %v", got, updateErr)
	}
}

func TestNumberChangeRollbackError_ErrorsIsUpdateErr(t *testing.T) {
	root := errors.New("root cause")
	wrapped := signalerrors.Wrap(signalerrors.ErrInternal, "wrapped", root)
	e := &NumberChangeRollbackError{
		DisplacedUUID: "uuid-2",
		UpdateErr:     wrapped,
		RestoreErr:    errors.New("restore"),
	}
	if !errors.Is(e, root) {
		t.Error("expected errors.Is to find root cause via Unwrap chain")
	}
}

func TestNumberChangeRollbackError_TypeAssertion(t *testing.T) {
	var err error = &NumberChangeRollbackError{
		DisplacedUUID: "uuid-3",
		UpdateErr:     errors.New("up"),
		RestoreErr:    errors.New("re"),
	}
	var target *NumberChangeRollbackError
	if !errors.As(err, &target) {
		t.Fatal("expected errors.As to succeed for *NumberChangeRollbackError")
	}
	if target.DisplacedUUID != "uuid-3" {
		t.Errorf("DisplacedUUID = %q, want uuid-3", target.DisplacedUUID)
	}
}
