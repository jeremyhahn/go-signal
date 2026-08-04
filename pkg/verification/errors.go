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

// RequestCodeRateLimitedError is returned by Manager.SendCode when the
// caller has already requested a code for this session and the per-session
// cooldown has not yet elapsed. Handlers surface RetryAfter to the client
// so it can render the "may_request_sms"/"next_sms_seconds" hint.
type RequestCodeRateLimitedError struct {
	SessionID  string
	RetryAfter time.Duration
}

func (e *RequestCodeRateLimitedError) Error() string {
	return "verification code request rate-limited for session " + e.SessionID +
		"; retry after " + e.RetryAfter.String()
}

// CaptchaRequiredError indicates the session must satisfy a captcha
// challenge before the next SendCode will succeed. The REST handler
// surfaces this as HTTP 409 with `requestedInformation: ["captcha"]`.
type CaptchaRequiredError struct {
	SessionID string
}

func (e *CaptchaRequiredError) Error() string {
	return "captcha required for session " + e.SessionID
}

// CaptchaCheckUnavailableError indicates the deployment is not configured
// with a CAPTCHA checker (no providers registered). Surfaced as HTTP 503
// so clients can retry against a properly provisioned region.
type CaptchaCheckUnavailableError struct{}

func (e *CaptchaCheckUnavailableError) Error() string {
	return "captcha verification not available on this server"
}

// CaptchaRejectedError indicates the submitted captcha did not verify with
// the upstream provider (or scored below the configured threshold). The
// REST handler surfaces this as HTTP 422 so clients distinguish "we
// couldn't reach the provider" from "you sent an invalid token".
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
