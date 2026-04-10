package push

import (
	"errors"
	"testing"
)

func TestSendError_Error(t *testing.T) {
	cause := errors.New("connection refused")
	e := &SendError{Provider: "apns", DeviceToken: "tok123", Cause: cause}
	want := "push/apns: failed to send to tok123: connection refused"
	if got := e.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSendError_Unwrap(t *testing.T) {
	cause := errors.New("root")
	e := &SendError{Provider: "fcm", DeviceToken: "tok", Cause: cause}
	if e.Unwrap() != cause {
		t.Error("Unwrap should return cause")
	}
}

func TestProviderNotConfiguredError_APNs(t *testing.T) {
	e := &ProviderNotConfiguredError{DeviceType: DeviceTypeAPNs}
	want := "push: APNs provider not configured"
	if got := e.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProviderNotConfiguredError_FCM(t *testing.T) {
	e := &ProviderNotConfiguredError{DeviceType: DeviceTypeFCM}
	want := "push: FCM provider not configured"
	if got := e.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestProviderNotConfiguredError_Unknown(t *testing.T) {
	e := &ProviderNotConfiguredError{DeviceType: DeviceType(99)}
	want := "push: unknown provider not configured"
	if got := e.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestInvalidTokenError_Error(t *testing.T) {
	e := &InvalidTokenError{Provider: "apns", DeviceToken: "bad-token"}
	want := "push/apns: invalid device token: bad-token"
	if got := e.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
