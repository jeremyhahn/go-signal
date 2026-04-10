package rest

import (
	"errors"
	"testing"
)

func TestDecodeError_ErrorWithCause(t *testing.T) {
	cause := errors.New("bad base64")
	e := &DecodeError{Message: "identity key", Cause: cause}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
	if e.Unwrap() != cause {
		t.Error("expected Unwrap to return cause")
	}
}

func TestDecodeError_ErrorWithoutCause(t *testing.T) {
	e := &DecodeError{Message: "identity key"}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
	if e.Unwrap() != nil {
		t.Error("expected nil from Unwrap")
	}
}

func TestAuthenticationError_Error(t *testing.T) {
	e := &AuthenticationError{Message: "invalid credentials"}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
}

func TestSessionNotFoundError_Error(t *testing.T) {
	e := &SessionNotFoundError{ID: "abc-123"}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
}

func TestListenError_Error(t *testing.T) {
	cause := errors.New("address in use")
	e := &ListenError{Addr: ":8080", Cause: cause}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
	if e.Unwrap() != cause {
		t.Error("expected Unwrap to return cause")
	}
}

func TestListenError_ErrorMessage(t *testing.T) {
	e := &ListenError{Addr: ":9090", Cause: errors.New("oops")}
	expected := "failed to listen on :9090: oops"
	if e.Error() != expected {
		t.Errorf("expected %q, got %q", expected, e.Error())
	}
}

func TestTLSError_Error(t *testing.T) {
	cause := errors.New("certificate expired")
	e := &TLSError{Cause: cause}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
	expected := "failed to load TLS certificates: certificate expired"
	if msg != expected {
		t.Errorf("expected %q, got %q", expected, msg)
	}
}

func TestTLSError_Unwrap(t *testing.T) {
	cause := errors.New("key mismatch")
	e := &TLSError{Cause: cause}
	if e.Unwrap() != cause {
		t.Error("expected Unwrap to return cause")
	}
}

func TestTLSError_ErrorsAs(t *testing.T) {
	cause := errors.New("bad cert")
	e := &TLSError{Cause: cause}
	var tlsErr *TLSError
	if !errors.As(e, &tlsErr) {
		t.Error("expected errors.As to match *TLSError")
	}
	if !errors.Is(e, cause) {
		t.Error("expected errors.Is to find cause through Unwrap")
	}
}

// --------------------------------------------------------------------------
// RequestBodyTooLargeError
// --------------------------------------------------------------------------

func TestRequestBodyTooLargeError_ErrorMessage(t *testing.T) {
	e := &RequestBodyTooLargeError{Limit: 256 * 1024}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
}

func TestRequestBodyTooLargeError_ZeroLimit(t *testing.T) {
	e := &RequestBodyTooLargeError{Limit: 0}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message for zero limit")
	}
}

func TestSessionExpiredError_Error(t *testing.T) {
	e := &SessionExpiredError{ID: "session-xyz"}
	msg := e.Error()
	expected := "verification session expired: session-xyz"
	if msg != expected {
		t.Errorf("expected %q, got %q", expected, msg)
	}
}

func TestSessionExpiredError_EmptyID(t *testing.T) {
	e := &SessionExpiredError{ID: ""}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message for empty ID")
	}
}

func TestSessionLimitExceededError_Error(t *testing.T) {
	e := &SessionLimitExceededError{Limit: 1000}
	msg := e.Error()
	expected := "verification session limit exceeded"
	if msg != expected {
		t.Errorf("expected %q, got %q", expected, msg)
	}
}

func TestSessionLimitExceededError_ZeroLimit(t *testing.T) {
	e := &SessionLimitExceededError{Limit: 0}
	msg := e.Error()
	if msg == "" {
		t.Error("expected non-empty error message for zero limit")
	}
}
