package verification

import (
	"strconv"
	"time"
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

// SessionAlreadyVerifiedError is returned by SendCode for a verified session; handlers return 409 with the session.
type SessionAlreadyVerifiedError struct {
	SessionID string
}

func (e *SessionAlreadyVerifiedError) Error() string {
	return "verification session already verified: " + e.SessionID
}

// RequestCodeRateLimitedError is returned by SendCode within the session cooldown; RetryAfter is the remaining wait.
type RequestCodeRateLimitedError struct {
	SessionID  string
	RetryAfter time.Duration
}

func (e *RequestCodeRateLimitedError) Error() string {
	return "verification code request rate-limited for session " + e.SessionID +
		"; retry after " + e.RetryAfter.String()
}

// CaptchaRequiredError means a captcha must be solved first; REST returns 409 with requestedInformation ["captcha"].
type CaptchaRequiredError struct {
	SessionID string
}

func (e *CaptchaRequiredError) Error() string {
	return "captcha required for session " + e.SessionID
}

// CaptchaCheckUnavailableError means no captcha provider is configured; REST returns 503.
type CaptchaCheckUnavailableError struct{}

func (e *CaptchaCheckUnavailableError) Error() string {
	return "captcha verification not available on this server"
}

// CaptchaRejectedError means the captcha failed or scored too low; REST returns 422.
type CaptchaRejectedError struct {
	SessionID string
	Reason    string
}

func (e *CaptchaRejectedError) Error() string {
	if e.Reason != "" {
		return "captcha rejected for session " + e.SessionID + ": " + e.Reason
	}
	return "captcha rejected for session " + e.SessionID
}
