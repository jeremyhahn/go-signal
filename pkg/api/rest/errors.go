// Package rest implements the Signal Server REST API layer.
package rest

// DecodeError indicates a failure to decode a request body.
type DecodeError struct {
	Message string
	Cause   error
}

func (e *DecodeError) Error() string {
	if e.Cause != nil {
		return "decode error: " + e.Message + ": " + e.Cause.Error()
	}
	return "decode error: " + e.Message
}

func (e *DecodeError) Unwrap() error {
	return e.Cause
}

// AuthenticationError indicates a failure to authenticate a request.
type AuthenticationError struct {
	Message string
}

func (e *AuthenticationError) Error() string {
	return "authentication error: " + e.Message
}

// SessionNotFoundError indicates the requested verification session does not exist.
type SessionNotFoundError struct {
	ID string
}

func (e *SessionNotFoundError) Error() string {
	return "verification session not found: " + e.ID
}

// SessionExpiredError indicates a verification session has passed its TTL.
type SessionExpiredError struct {
	ID string
}

func (e *SessionExpiredError) Error() string {
	return "verification session expired: " + e.ID
}

// SessionLimitExceededError indicates the server-wide session cap has been reached.
type SessionLimitExceededError struct {
	Limit int
}

func (e *SessionLimitExceededError) Error() string {
	return "verification session limit exceeded"
}

// RequestBodyTooLargeError indicates the request body exceeded the configured limit.
type RequestBodyTooLargeError struct {
	Limit int64
}

func (e *RequestBodyTooLargeError) Error() string {
	return "request body too large: exceeds limit"
}

// SessionPhoneNumberMismatchError indicates the verification session belongs to
// a different phone number than the one being registered.
type SessionPhoneNumberMismatchError struct {
	SessionID string
}

func (e *SessionPhoneNumberMismatchError) Error() string {
	return "verification session phone number mismatch for session: " + e.SessionID
}

// SessionNotVerifiedError indicates the verification session has not completed
// the code verification step.
type SessionNotVerifiedError struct {
	SessionID string
}

func (e *SessionNotVerifiedError) Error() string {
	return "verification session not verified: " + e.SessionID
}
