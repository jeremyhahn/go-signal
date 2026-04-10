package websocket

import (
	"errors"
	"fmt"
	"testing"
)

func TestSessionClosedError_Error(t *testing.T) {
	tests := []struct {
		name     string
		uuid     string
		deviceID uint64
		want     string
	}{
		{
			name:     "standard uuid",
			uuid:     "abc-123",
			deviceID: 1,
			want:     "websocket session closed for abc-123",
		},
		{
			name:     "empty uuid",
			uuid:     "",
			deviceID: 0,
			want:     "websocket session closed for ",
		},
		{
			name:     "long uuid",
			uuid:     "550e8400-e29b-41d4-a716-446655440000",
			deviceID: 42,
			want:     "websocket session closed for 550e8400-e29b-41d4-a716-446655440000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &SessionClosedError{UUID: tt.uuid, DeviceID: tt.deviceID}
			got := e.Error()
			if got != tt.want {
				t.Errorf("SessionClosedError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSessionClosedError_TypeAssertion(t *testing.T) {
	var err error = &SessionClosedError{UUID: "test-uuid", DeviceID: 5}

	var target *SessionClosedError
	if !errors.As(err, &target) {
		t.Fatal("expected errors.As to succeed for *SessionClosedError")
	}
	if target.UUID != "test-uuid" {
		t.Errorf("UUID = %q, want %q", target.UUID, "test-uuid")
	}
	if target.DeviceID != 5 {
		t.Errorf("DeviceID = %d, want %d", target.DeviceID, 5)
	}
}

func TestSessionClosedError_ImplementsError(t *testing.T) {
	var _ error = &SessionClosedError{}
}

func TestDeliveryFailedError_Error(t *testing.T) {
	tests := []struct {
		name     string
		uuid     string
		deviceID uint64
		cause    error
		want     string
	}{
		{
			name:     "with cause",
			uuid:     "user-1",
			deviceID: 1,
			cause:    fmt.Errorf("connection reset"),
			want:     "message delivery failed for user-1: connection reset",
		},
		{
			name:     "nil cause",
			uuid:     "user-2",
			deviceID: 2,
			cause:    nil,
			want:     "message delivery failed for user-2",
		},
		{
			name:     "empty uuid with cause",
			uuid:     "",
			deviceID: 0,
			cause:    fmt.Errorf("timeout"),
			want:     "message delivery failed for : timeout",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &DeliveryFailedError{UUID: tt.uuid, DeviceID: tt.deviceID, Cause: tt.cause}
			got := e.Error()
			if got != tt.want {
				t.Errorf("DeliveryFailedError.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDeliveryFailedError_TypeAssertion(t *testing.T) {
	cause := fmt.Errorf("write timeout")
	var err error = &DeliveryFailedError{UUID: "acc-1", DeviceID: 3, Cause: cause}

	var target *DeliveryFailedError
	if !errors.As(err, &target) {
		t.Fatal("expected errors.As to succeed for *DeliveryFailedError")
	}
	if target.UUID != "acc-1" {
		t.Errorf("UUID = %q, want %q", target.UUID, "acc-1")
	}
	if target.DeviceID != 3 {
		t.Errorf("DeviceID = %d, want %d", target.DeviceID, 3)
	}
}

func TestDeliveryFailedError_Unwrap(t *testing.T) {
	cause := fmt.Errorf("underlying network error")
	e := &DeliveryFailedError{UUID: "uuid-1", DeviceID: 1, Cause: cause}

	unwrapped := e.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap() returned %v, want %v", unwrapped, cause)
	}
}

func TestDeliveryFailedError_UnwrapNil(t *testing.T) {
	e := &DeliveryFailedError{UUID: "uuid-1", DeviceID: 1, Cause: nil}

	unwrapped := e.Unwrap()
	if unwrapped != nil {
		t.Errorf("Unwrap() returned %v, want nil", unwrapped)
	}
}

func TestDeliveryFailedError_ErrorsIs(t *testing.T) {
	root := fmt.Errorf("root cause")
	wrapped := fmt.Errorf("mid: %w", root)
	e := &DeliveryFailedError{UUID: "u", DeviceID: 1, Cause: wrapped}

	if !errors.Is(e, root) {
		t.Error("expected errors.Is to find root cause through Unwrap chain")
	}
}

func TestDeliveryFailedError_ImplementsError(t *testing.T) {
	var _ error = &DeliveryFailedError{}
}

func TestSessionClosedError_FieldsPreserved(t *testing.T) {
	e := &SessionClosedError{UUID: "preserved-uuid", DeviceID: 99}
	if e.UUID != "preserved-uuid" {
		t.Errorf("UUID = %q, want %q", e.UUID, "preserved-uuid")
	}
	if e.DeviceID != 99 {
		t.Errorf("DeviceID = %d, want %d", e.DeviceID, 99)
	}
}

func TestDeliveryFailedError_FieldsPreserved(t *testing.T) {
	cause := fmt.Errorf("test")
	e := &DeliveryFailedError{UUID: "preserved-uuid", DeviceID: 77, Cause: cause}
	if e.UUID != "preserved-uuid" {
		t.Errorf("UUID = %q, want %q", e.UUID, "preserved-uuid")
	}
	if e.DeviceID != 77 {
		t.Errorf("DeviceID = %d, want %d", e.DeviceID, 77)
	}
	if e.Cause != cause {
		t.Errorf("Cause = %v, want %v", e.Cause, cause)
	}
}
