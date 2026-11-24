package captcha

import "context"

// CaptchaVerifier verifies a client token, remote IP and site key against an external CAPTCHA service.
type CaptchaVerifier interface {
	// Verify returns the service's result; an error is a transport or configuration problem, a failed check is Success == false.
	Verify(ctx context.Context, token string, remoteIP string, siteKey string) (*VerifyResult, error)
}

// VerifyResult is a CAPTCHA service's parsed response.
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
