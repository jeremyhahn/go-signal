package calling

import (
	"errors"
	"testing"
)

// --- PeerNotConnectedError ---

func TestPeerNotConnectedError_Error(t *testing.T) {
	err := &PeerNotConnectedError{UUID: "peer-uuid-1"}
	want := "peer not connected: peer-uuid-1"
	if got := err.Error(); got != want {
		t.Errorf("PeerNotConnectedError.Error() = %q, want %q", got, want)
	}
}

func TestPeerNotConnectedError_EmptyUUID(t *testing.T) {
	err := &PeerNotConnectedError{}
	want := "peer not connected: "
	if got := err.Error(); got != want {
		t.Errorf("PeerNotConnectedError.Error() = %q, want %q", got, want)
	}
}

func TestPeerNotConnectedError_Unwrap(t *testing.T) {
	err := &PeerNotConnectedError{UUID: "some-uuid"}
	if err.Unwrap() != nil {
		t.Errorf("PeerNotConnectedError.Unwrap() = %v, want nil", err.Unwrap())
	}
}

func TestPeerNotConnectedError_ErrorsAs(t *testing.T) {
	err := &PeerNotConnectedError{UUID: "peer-uuid"}
	var target *PeerNotConnectedError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for PeerNotConnectedError")
	}
	if target.UUID != "peer-uuid" {
		t.Errorf("got UUID %q, want %q", target.UUID, "peer-uuid")
	}
}

// --- CallNotFoundError ---

func TestCallNotFoundError_Error(t *testing.T) {
	err := &CallNotFoundError{CallID: "call-abc-123"}
	want := "call not found: call-abc-123"
	if got := err.Error(); got != want {
		t.Errorf("CallNotFoundError.Error() = %q, want %q", got, want)
	}
}

func TestCallNotFoundError_EmptyCallID(t *testing.T) {
	err := &CallNotFoundError{}
	want := "call not found: "
	if got := err.Error(); got != want {
		t.Errorf("CallNotFoundError.Error() = %q, want %q", got, want)
	}
}

func TestCallNotFoundError_Unwrap(t *testing.T) {
	err := &CallNotFoundError{CallID: "call-xyz"}
	if err.Unwrap() != nil {
		t.Errorf("CallNotFoundError.Unwrap() = %v, want nil", err.Unwrap())
	}
}

func TestCallNotFoundError_ErrorsAs(t *testing.T) {
	err := &CallNotFoundError{CallID: "my-call"}
	var target *CallNotFoundError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for CallNotFoundError")
	}
	if target.CallID != "my-call" {
		t.Errorf("got CallID %q, want %q", target.CallID, "my-call")
	}
}

// --- CallAlreadyActiveError ---

func TestCallAlreadyActiveError_Error(t *testing.T) {
	err := &CallAlreadyActiveError{UUID: "user-uuid-active"}
	want := "call already active for user: user-uuid-active"
	if got := err.Error(); got != want {
		t.Errorf("CallAlreadyActiveError.Error() = %q, want %q", got, want)
	}
}

func TestCallAlreadyActiveError_EmptyUUID(t *testing.T) {
	err := &CallAlreadyActiveError{}
	want := "call already active for user: "
	if got := err.Error(); got != want {
		t.Errorf("CallAlreadyActiveError.Error() = %q, want %q", got, want)
	}
}

func TestCallAlreadyActiveError_Unwrap(t *testing.T) {
	err := &CallAlreadyActiveError{UUID: "uuid"}
	if err.Unwrap() != nil {
		t.Errorf("CallAlreadyActiveError.Unwrap() = %v, want nil", err.Unwrap())
	}
}

func TestCallAlreadyActiveError_ErrorsAs(t *testing.T) {
	err := &CallAlreadyActiveError{UUID: "active-user"}
	var target *CallAlreadyActiveError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for CallAlreadyActiveError")
	}
	if target.UUID != "active-user" {
		t.Errorf("got UUID %q, want %q", target.UUID, "active-user")
	}
}

// --- InvalidCallSignalError ---

func TestInvalidCallSignalError_Error(t *testing.T) {
	err := &InvalidCallSignalError{Message: "missing offer field"}
	want := "invalid call signal: missing offer field"
	if got := err.Error(); got != want {
		t.Errorf("InvalidCallSignalError.Error() = %q, want %q", got, want)
	}
}

func TestInvalidCallSignalError_EmptyMessage(t *testing.T) {
	err := &InvalidCallSignalError{}
	want := "invalid call signal: "
	if got := err.Error(); got != want {
		t.Errorf("InvalidCallSignalError.Error() = %q, want %q", got, want)
	}
}

func TestInvalidCallSignalError_Unwrap(t *testing.T) {
	err := &InvalidCallSignalError{Message: "bad signal"}
	if err.Unwrap() != nil {
		t.Errorf("InvalidCallSignalError.Unwrap() = %v, want nil", err.Unwrap())
	}
}

func TestInvalidCallSignalError_ErrorsAs(t *testing.T) {
	err := &InvalidCallSignalError{Message: "malformed"}
	var target *InvalidCallSignalError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for InvalidCallSignalError")
	}
	if target.Message != "malformed" {
		t.Errorf("got message %q, want %q", target.Message, "malformed")
	}
}
