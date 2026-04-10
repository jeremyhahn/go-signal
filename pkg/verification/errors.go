package verification

import (
	"strconv"
)

// SessionNotFoundError indicates the requested verification session does not exist.
type SessionNotFoundError struct {
	SessionID string
}

func (e *SessionNotFoundError) Error() string {
	return "verification session not found: " + e.SessionID
}

// SessionExpiredError indicates the verification session has expired.
type SessionExpiredError struct {
	SessionID string
}

func (e *SessionExpiredError) Error() string {
	return "verification session expired: " + e.SessionID
}

// CodeExpiredError indicates the verification code has expired.
type CodeExpiredError struct {
	SessionID string
}

func (e *CodeExpiredError) Error() string {
	return "verification code expired: " + e.SessionID
}

// MaxAttemptsExceededError indicates the maximum number of verification
// attempts has been exceeded.
type MaxAttemptsExceededError struct {
	SessionID   string
	MaxAttempts int
}

func (e *MaxAttemptsExceededError) Error() string {
	return "max verification attempts exceeded for session " + e.SessionID +
		": limit " + strconv.Itoa(e.MaxAttempts)
}

// InvalidCodeError indicates the submitted verification code is incorrect.
type InvalidCodeError struct {
	SessionID string
}

func (e *InvalidCodeError) Error() string {
	return "invalid verification code for session: " + e.SessionID
}

// TransportError indicates a failure in the verification transport layer.
type TransportError struct {
	Transport   string
	Destination string
	Cause       error
}

func (e *TransportError) Error() string {
	msg := "verification transport " + e.Transport + " failed for " + e.Destination
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying cause of the transport error.
func (e *TransportError) Unwrap() error {
	return e.Cause
}

// CarrierNotFoundError indicates the specified carrier is not recognized.
type CarrierNotFoundError struct {
	Carrier string
}

func (e *CarrierNotFoundError) Error() string {
	return "carrier not found: " + e.Carrier
}

// SessionLimitExceededError indicates the server-wide session cap has been
// reached. The caller should return HTTP 429 to the client.
type SessionLimitExceededError struct {
	Limit int
}

func (e *SessionLimitExceededError) Error() string {
	return "verification session limit exceeded: max " + strconv.Itoa(e.Limit)
}
