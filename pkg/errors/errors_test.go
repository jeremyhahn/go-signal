package errors

import (
	"errors"
	"testing"
)

func TestErrorCode_Constants(t *testing.T) {
	tests := []struct {
		name string
		code ErrorCode
		want int
	}{
		{"ErrInternal", ErrInternal, 0},
		{"ErrNotFound", ErrNotFound, 1},
		{"ErrAlreadyExists", ErrAlreadyExists, 2},
		{"ErrInvalidArgument", ErrInvalidArgument, 3},
		{"ErrUnauthenticated", ErrUnauthenticated, 4},
		{"ErrPermissionDenied", ErrPermissionDenied, 5},
		{"ErrRateLimited", ErrRateLimited, 6},
		{"ErrUnavailable", ErrUnavailable, 7},
		{"ErrAccountNotFound", ErrAccountNotFound, 8},
		{"ErrAccountDisabled", ErrAccountDisabled, 9},
		{"ErrDeviceLimitExceeded", ErrDeviceLimitExceeded, 10},
		{"ErrRegistrationLocked", ErrRegistrationLocked, 11},
		{"ErrDeviceNotFound", ErrDeviceNotFound, 12},
		{"ErrMismatchedDevices", ErrMismatchedDevices, 13},
		{"ErrStaleDevices", ErrStaleDevices, 14},
		{"ErrMessageTooLarge", ErrMessageTooLarge, 15},
		{"ErrPreKeyNotAvailable", ErrPreKeyNotAvailable, 16},
		{"ErrPreKeyCountExceeded", ErrPreKeyCountExceeded, 17},
		{"ErrProfileNotFound", ErrProfileNotFound, 18},
		{"ErrProfileVersionConflict", ErrProfileVersionConflict, 19},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.code) != tt.want {
				t.Errorf("got %d, want %d", int(tt.code), tt.want)
			}
		})
	}
}

func TestErrorCode_Uniqueness(t *testing.T) {
	codes := []ErrorCode{
		ErrInternal, ErrNotFound, ErrAlreadyExists, ErrInvalidArgument,
		ErrUnauthenticated, ErrPermissionDenied, ErrRateLimited, ErrUnavailable,
		ErrAccountNotFound, ErrAccountDisabled, ErrDeviceLimitExceeded,
		ErrRegistrationLocked, ErrDeviceNotFound, ErrMismatchedDevices,
		ErrStaleDevices, ErrMessageTooLarge, ErrPreKeyNotAvailable,
		ErrPreKeyCountExceeded, ErrProfileNotFound, ErrProfileVersionConflict,
	}
	seen := make(map[ErrorCode]bool, len(codes))
	for _, c := range codes {
		if seen[c] {
			t.Fatalf("duplicate error code: %d", c)
		}
		seen[c] = true
	}
}

func TestSignalError_Error_WithoutCause(t *testing.T) {
	e := &SignalError{Code: ErrInternal, Message: "something broke"}
	if got := e.Error(); got != "something broke" {
		t.Errorf("got %q, want %q", got, "something broke")
	}
}

func TestSignalError_Error_WithCause(t *testing.T) {
	cause := errors.New("disk full")
	e := &SignalError{Code: ErrInternal, Message: "storage failure", Cause: cause}
	want := "storage failure: disk full"
	if got := e.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSignalError_Unwrap_NilCause(t *testing.T) {
	e := &SignalError{Code: ErrInternal, Message: "no cause"}
	if e.Unwrap() != nil {
		t.Errorf("expected nil, got %v", e.Unwrap())
	}
}

func TestSignalError_Unwrap_WithCause(t *testing.T) {
	cause := errors.New("root cause")
	e := &SignalError{Code: ErrInternal, Message: "wrapped", Cause: cause}
	if e.Unwrap() != cause {
		t.Errorf("got %v, want %v", e.Unwrap(), cause)
	}
}

func TestNew_BasicError(t *testing.T) {
	e := New(ErrNotFound, "not found")
	if e.Code != ErrNotFound {
		t.Errorf("got code %d, want %d", e.Code, ErrNotFound)
	}
	if e.Message != "not found" {
		t.Errorf("got message %q, want %q", e.Message, "not found")
	}
	if e.Cause != nil {
		t.Errorf("expected nil cause, got %v", e.Cause)
	}
}

func TestNew_EmptyMessage(t *testing.T) {
	e := New(ErrInternal, "")
	if e.Error() != "" {
		t.Errorf("got %q, want empty string", e.Error())
	}
}

func TestWrap_BasicError(t *testing.T) {
	cause := errors.New("underlying")
	e := Wrap(ErrUnavailable, "service down", cause)
	if e.Code != ErrUnavailable {
		t.Errorf("got code %d, want %d", e.Code, ErrUnavailable)
	}
	if e.Message != "service down" {
		t.Errorf("got message %q, want %q", e.Message, "service down")
	}
	if e.Cause != cause {
		t.Errorf("got cause %v, want %v", e.Cause, cause)
	}
}

func TestWrap_NilCause(t *testing.T) {
	e := Wrap(ErrInternal, "no cause", nil)
	if e.Cause != nil {
		t.Errorf("expected nil cause, got %v", e.Cause)
	}
	if got := e.Error(); got != "no cause" {
		t.Errorf("got %q, want %q", got, "no cause")
	}
}

func TestWrap_ErrorsIs(t *testing.T) {
	cause := errors.New("root")
	e := Wrap(ErrInternal, "wrapped", cause)
	if !errors.Is(e, cause) {
		t.Error("errors.Is should find the wrapped cause")
	}
}

func TestNewAccountNotFoundError_Basic(t *testing.T) {
	e := NewAccountNotFoundError("account abc123 not found")
	if e.Code != ErrAccountNotFound {
		t.Errorf("got code %d, want %d", e.Code, ErrAccountNotFound)
	}
	if e.Message != "account abc123 not found" {
		t.Errorf("got message %q, want %q", e.Message, "account abc123 not found")
	}
}

func TestNewAccountNotFoundError_TypeAssertion(t *testing.T) {
	var err error = NewAccountNotFoundError("missing")
	var target *AccountNotFoundError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *AccountNotFoundError")
	}
	if target.Message != "missing" {
		t.Errorf("got message %q, want %q", target.Message, "missing")
	}
}

func TestNewAccountNotFoundError_ErrorString(t *testing.T) {
	e := NewAccountNotFoundError("user xyz")
	if got := e.Error(); got != "user xyz" {
		t.Errorf("got %q, want %q", got, "user xyz")
	}
}

func TestNewDeviceNotFoundError_Basic(t *testing.T) {
	e := NewDeviceNotFoundError("device 42")
	if e.Code != ErrDeviceNotFound {
		t.Errorf("got code %d, want %d", e.Code, ErrDeviceNotFound)
	}
	if e.Error() != "device 42" {
		t.Errorf("got %q, want %q", e.Error(), "device 42")
	}
}

func TestNewDeviceNotFoundError_TypeAssertion(t *testing.T) {
	var err error = NewDeviceNotFoundError("dev1")
	var target *DeviceNotFoundError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *DeviceNotFoundError")
	}
}

func TestNewDeviceLimitExceededError_Basic(t *testing.T) {
	e := NewDeviceLimitExceededError(6, 7)
	if e.Code != ErrDeviceLimitExceeded {
		t.Errorf("got code %d, want %d", e.Code, ErrDeviceLimitExceeded)
	}
	if e.MaxDevices != 6 {
		t.Errorf("got max %d, want 6", e.MaxDevices)
	}
	if e.Current != 7 {
		t.Errorf("got current %d, want 7", e.Current)
	}
	if e.Error() != "device limit exceeded" {
		t.Errorf("got %q, want %q", e.Error(), "device limit exceeded")
	}
}

func TestNewDeviceLimitExceededError_TypeAssertion(t *testing.T) {
	var err error = NewDeviceLimitExceededError(10, 11)
	var target *DeviceLimitExceededError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *DeviceLimitExceededError")
	}
	if target.MaxDevices != 10 || target.Current != 11 {
		t.Errorf("got max=%d current=%d, want max=10 current=11", target.MaxDevices, target.Current)
	}
}

func TestNewRateLimitedError_Basic(t *testing.T) {
	e := NewRateLimitedError(60)
	if e.Code != ErrRateLimited {
		t.Errorf("got code %d, want %d", e.Code, ErrRateLimited)
	}
	if e.RetryAfterSeconds != 60 {
		t.Errorf("got retry %d, want 60", e.RetryAfterSeconds)
	}
	if e.Error() != "rate limit exceeded" {
		t.Errorf("got %q, want %q", e.Error(), "rate limit exceeded")
	}
}

func TestNewRateLimitedError_ZeroRetry(t *testing.T) {
	e := NewRateLimitedError(0)
	if e.RetryAfterSeconds != 0 {
		t.Errorf("got retry %d, want 0", e.RetryAfterSeconds)
	}
}

func TestNewRateLimitedError_TypeAssertion(t *testing.T) {
	var err error = NewRateLimitedError(30)
	var target *RateLimitedError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *RateLimitedError")
	}
}

func TestNewMismatchedDevicesError_Basic(t *testing.T) {
	missing := []uint64{1, 2}
	extra := []uint64{3}
	e := NewMismatchedDevicesError(missing, extra)
	if e.Code != ErrMismatchedDevices {
		t.Errorf("got code %d, want %d", e.Code, ErrMismatchedDevices)
	}
	if len(e.MissingDevices) != 2 {
		t.Errorf("got %d missing, want 2", len(e.MissingDevices))
	}
	if len(e.ExtraDevices) != 1 {
		t.Errorf("got %d extra, want 1", len(e.ExtraDevices))
	}
	if e.Error() != "mismatched devices" {
		t.Errorf("got %q, want %q", e.Error(), "mismatched devices")
	}
}

func TestNewMismatchedDevicesError_NilSlices(t *testing.T) {
	e := NewMismatchedDevicesError(nil, nil)
	if e.MissingDevices != nil {
		t.Errorf("expected nil missing, got %v", e.MissingDevices)
	}
	if e.ExtraDevices != nil {
		t.Errorf("expected nil extra, got %v", e.ExtraDevices)
	}
}

func TestNewMismatchedDevicesError_TypeAssertion(t *testing.T) {
	var err error = NewMismatchedDevicesError([]uint64{1}, []uint64{2})
	var target *MismatchedDevicesError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *MismatchedDevicesError")
	}
}

func TestNewStaleDevicesError_Basic(t *testing.T) {
	stale := []uint64{5, 6, 7}
	e := NewStaleDevicesError(stale)
	if e.Code != ErrStaleDevices {
		t.Errorf("got code %d, want %d", e.Code, ErrStaleDevices)
	}
	if len(e.StaleDevices) != 3 {
		t.Errorf("got %d stale, want 3", len(e.StaleDevices))
	}
	if e.Error() != "stale devices" {
		t.Errorf("got %q, want %q", e.Error(), "stale devices")
	}
}

func TestNewStaleDevicesError_NilSlice(t *testing.T) {
	e := NewStaleDevicesError(nil)
	if e.StaleDevices != nil {
		t.Errorf("expected nil, got %v", e.StaleDevices)
	}
}

func TestNewStaleDevicesError_TypeAssertion(t *testing.T) {
	var err error = NewStaleDevicesError([]uint64{1})
	var target *StaleDevicesError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *StaleDevicesError")
	}
}

func TestSignalError_ImplementsErrorInterface(t *testing.T) {
	var _ error = &SignalError{}
	var _ error = &AccountNotFoundError{}
	var _ error = &DeviceNotFoundError{}
	var _ error = &DeviceLimitExceededError{}
	var _ error = &RateLimitedError{}
	var _ error = &MismatchedDevicesError{}
	var _ error = &StaleDevicesError{}
}

func TestSignalError_ErrorChaining(t *testing.T) {
	root := errors.New("io timeout")
	mid := Wrap(ErrUnavailable, "db failed", root)
	top := Wrap(ErrInternal, "handler failed", mid)

	if !errors.Is(top, root) {
		t.Error("should be able to find root cause through chain")
	}
	if !errors.Is(top, mid) {
		t.Error("should be able to find mid cause through chain")
	}
}
