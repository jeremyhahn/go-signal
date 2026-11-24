package captcha

// ChallengeFailedError indicates that a challenge response verification
// failed. The Message field describes the reason for failure.
type ChallengeFailedError struct {
	Message string
}

// Error returns a human-readable description of the challenge failure.
func (e *ChallengeFailedError) Error() string {
	return "challenge failed: " + e.Message
}

// CaptchaUnavailableError indicates the server has no CAPTCHA backend
// configured, so a submission can be neither accepted nor rejected on its
// merits. Callers map it to HTTP 503: refusing the request is correct, and
// silently accepting an unverifiable token would defeat the challenge.
type CaptchaUnavailableError struct{}

// Error returns a human-readable description.
func (e *CaptchaUnavailableError) Error() string {
	return "no captcha provider is configured"
}

// InvalidChallengeTypeError indicates that an unrecognized challenge type
// was submitted.
type InvalidChallengeTypeError struct {
	Type string
}

// Error returns a human-readable description of the invalid challenge type.
func (e *InvalidChallengeTypeError) Error() string {
	return "invalid challenge type: " + e.Type
}

// CaptchaVerificationFailedError is returned by CaptchaManager when the
// upstream CAPTCHA service rejects the token or the score falls below the
// configured threshold.
type CaptchaVerificationFailedError struct {
	// ErrorCodes holds the provider-specific codes returned by the upstream
	// service. Empty when the failure is due to a low score.
	ErrorCodes []string
}

// Error returns a human-readable description.
func (e *CaptchaVerificationFailedError) Error() string {
	if len(e.ErrorCodes) == 0 {
		return "captcha verification failed: score below threshold"
	}
	msg := "captcha verification failed"
	for _, c := range e.ErrorCodes {
		msg += ": " + c
	}
	return msg
}

// CaptchaNetworkError indicates that the HTTP request to the upstream CAPTCHA
// service could not be completed.
type CaptchaNetworkError struct {
	// Provider names the CAPTCHA backend ("hcaptcha", "recaptcha", …).
	Provider string
	Cause    error
}

// Error returns a human-readable description.
func (e *CaptchaNetworkError) Error() string {
	return "captcha network error (" + e.Provider + "): " + e.Cause.Error()
}

// Unwrap returns the underlying transport error.
func (e *CaptchaNetworkError) Unwrap() error { return e.Cause }

// CaptchaParseError indicates that the response body returned by the upstream
// CAPTCHA service could not be decoded.
type CaptchaParseError struct {
	// Provider names the CAPTCHA backend.
	Provider string
	Cause    error
}

// Error returns a human-readable description.
func (e *CaptchaParseError) Error() string {
	return "captcha parse error (" + e.Provider + "): " + e.Cause.Error()
}

// Unwrap returns the underlying decode error.
func (e *CaptchaParseError) Unwrap() error { return e.Cause }

// HCaptchaConfigError indicates an invalid HCaptchaVerifier configuration.
type HCaptchaConfigError struct {
	Message string
}

// Error returns a human-readable description.
func (e *HCaptchaConfigError) Error() string {
	return "hcaptcha config error: " + e.Message
}

// ReCAPTCHAConfigError indicates an invalid ReCAPTCHAVerifier configuration.
type ReCAPTCHAConfigError struct {
	Message string
}

// Error returns a human-readable description.
func (e *ReCAPTCHAConfigError) Error() string {
	return "recaptcha config error: " + e.Message
}

// InvalidTokenFormatError indicates the captcha submission did not have the
// expected dotted layout `provider.sitekey.action.token`.
type InvalidTokenFormatError struct {
	Reason string
}

// Error returns a human-readable description.
func (e *InvalidTokenFormatError) Error() string {
	return "invalid captcha token format: " + e.Reason
}

// InvalidActionError indicates the action slot did not parse to a known
// Action value, or did not match the action expected by the call site.
type InvalidActionError struct {
	Action string
}

// Error returns a human-readable description.
func (e *InvalidActionError) Error() string {
	return "invalid captcha action: " + e.Action
}

// UnknownProviderError indicates the provider slot named a captcha scheme
// not configured for this server.
type UnknownProviderError struct {
	Provider string
}

// Error returns a human-readable description.
func (e *UnknownProviderError) Error() string {
	return "unknown captcha provider: " + e.Provider
}

// InvalidSiteKeyError indicates the site-key slot was not on the
// per-action allowlist of the resolved provider.
type InvalidSiteKeyError struct {
	SiteKey string
	Action  Action
}

// Error returns a human-readable description.
func (e *InvalidSiteKeyError) Error() string {
	return "invalid captcha site key " + e.SiteKey + " for action " + string(e.Action)
}

// ShortCodeUnsupportedError indicates the submission used the `-short`
// provider suffix but the deployment did not configure a ShortCodeExpander.
type ShortCodeUnsupportedError struct{}

// Error returns a human-readable description.
func (e *ShortCodeUnsupportedError) Error() string {
	return "short-code captcha submissions are not enabled"
}
