package verification

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSessionNotFoundError(t *testing.T) {
	t.Parallel()
	err := &SessionNotFoundError{SessionID: "sess-1"}
	assert.Equal(t, "verification session not found: sess-1", err.Error())
}

func TestSessionNotFoundError_ErrorAs(t *testing.T) {
	t.Parallel()
	err := &SessionNotFoundError{SessionID: "sess-1"}
	var target *SessionNotFoundError
	assert.ErrorAs(t, err, &target)
	assert.Equal(t, "sess-1", target.SessionID)
}

func TestSessionExpiredError(t *testing.T) {
	t.Parallel()
	err := &SessionExpiredError{SessionID: "sess-2"}
	assert.Equal(t, "verification session expired: sess-2", err.Error())
}

func TestSessionExpiredError_ErrorAs(t *testing.T) {
	t.Parallel()
	err := &SessionExpiredError{SessionID: "sess-2"}
	var target *SessionExpiredError
	assert.ErrorAs(t, err, &target)
	assert.Equal(t, "sess-2", target.SessionID)
}

func TestCodeExpiredError(t *testing.T) {
	t.Parallel()
	err := &CodeExpiredError{SessionID: "sess-3"}
	assert.Equal(t, "verification code expired: sess-3", err.Error())
}

func TestCodeExpiredError_ErrorAs(t *testing.T) {
	t.Parallel()
	err := &CodeExpiredError{SessionID: "sess-3"}
	var target *CodeExpiredError
	assert.ErrorAs(t, err, &target)
	assert.Equal(t, "sess-3", target.SessionID)
}

func TestMaxAttemptsExceededError(t *testing.T) {
	t.Parallel()
	err := &MaxAttemptsExceededError{SessionID: "sess-4", MaxAttempts: 3}
	assert.Equal(t, "max verification attempts exceeded for session sess-4: limit 3", err.Error())
}

func TestMaxAttemptsExceededError_ErrorAs(t *testing.T) {
	t.Parallel()
	err := &MaxAttemptsExceededError{SessionID: "sess-4", MaxAttempts: 3}
	var target *MaxAttemptsExceededError
	assert.ErrorAs(t, err, &target)
	assert.Equal(t, "sess-4", target.SessionID)
	assert.Equal(t, 3, target.MaxAttempts)
}

func TestInvalidCodeError(t *testing.T) {
	t.Parallel()
	err := &InvalidCodeError{SessionID: "sess-5"}
	assert.Equal(t, "invalid verification code for session: sess-5", err.Error())
}

func TestInvalidCodeError_ErrorAs(t *testing.T) {
	t.Parallel()
	err := &InvalidCodeError{SessionID: "sess-5"}
	var target *InvalidCodeError
	assert.ErrorAs(t, err, &target)
	assert.Equal(t, "sess-5", target.SessionID)
}

func TestTransportError_WithCause(t *testing.T) {
	t.Parallel()
	cause := errors.New("connection refused")
	err := &TransportError{Transport: "smtp", Destination: "+15551234567", Cause: cause}
	assert.Equal(t, "verification transport smtp failed for +15551234567: connection refused", err.Error())
}

func TestTransportError_WithoutCause(t *testing.T) {
	t.Parallel()
	err := &TransportError{Transport: "smtp", Destination: "+15551234567"}
	assert.Equal(t, "verification transport smtp failed for +15551234567", err.Error())
}

func TestTransportError_Unwrap(t *testing.T) {
	t.Parallel()
	cause := errors.New("timeout")
	err := &TransportError{Transport: "test", Destination: "dest", Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
}

func TestTransportError_UnwrapNil(t *testing.T) {
	t.Parallel()
	err := &TransportError{Transport: "test", Destination: "dest"}
	assert.Nil(t, err.Unwrap())
}

func TestCarrierNotFoundError(t *testing.T) {
	t.Parallel()
	err := &CarrierNotFoundError{Carrier: "unknown"}
	assert.Equal(t, "carrier not found: unknown", err.Error())
}

func TestCarrierNotFoundError_ErrorAs(t *testing.T) {
	t.Parallel()
	err := &CarrierNotFoundError{Carrier: "unknown"}
	var target *CarrierNotFoundError
	assert.ErrorAs(t, err, &target)
	assert.Equal(t, "unknown", target.Carrier)
}

func TestSessionLimitExceededError(t *testing.T) {
	t.Parallel()
	err := &SessionLimitExceededError{Limit: 10000}
	assert.Contains(t, err.Error(), "10000")
	assert.Contains(t, err.Error(), "session limit exceeded")
}

func TestSessionLimitExceededError_ErrorAs(t *testing.T) {
	t.Parallel()
	err := &SessionLimitExceededError{Limit: 5}
	var target *SessionLimitExceededError
	assert.ErrorAs(t, err, &target)
	assert.Equal(t, 5, target.Limit)
}
