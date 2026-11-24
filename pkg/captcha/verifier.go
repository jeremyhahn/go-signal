package captcha

import "context"

// CaptchaVerifier is the interface implemented by all CAPTCHA verification
// backends. Callers submit the client-supplied token, the remote IP address of
// the submitting client, and the site key that was used to render the widget.
// The backend contacts the external verification service and returns a
// VerifyResult describing the outcome.
type CaptchaVerifier interface {
	// Verify contacts the upstream CAPTCHA service and returns the result.
	// A non-nil error indicates a transport or configuration problem; a
	// failed verification is represented by VerifyResult.Success == false.
	Verify(ctx context.Context, token string, remoteIP string, siteKey string) (*VerifyResult, error)
}

// VerifyResult holds the parsed response returned by a CAPTCHA verification
// service.
type VerifyResult struct {
	// Success is true when the upstream service accepted the token.
	Success bool

	// Score is the confidence score in the range [0.0, 1.0] returned by
	// reCAPTCHA v3. For services that do not emit a score the value is 0.
	Score float64

	// Action is the action name the client embedded in the token (reCAPTCHA
	// v3 only). Empty for other providers.
	Action string

	// Hostname is the hostname that was validated by the upstream service.
	Hostname string

	// ErrorCodes contains the provider-specific error codes returned on
	// failure. Empty on success.
	ErrorCodes []string
}
