// Package verification provides phone number verification flows for the
// Signal server, including session management, code generation, and
// pluggable transport delivery.
package verification

import "time"

// VerificationSession tracks the state of a phone number verification flow.
type VerificationSession struct {
	ID                   string    `json:"id"`
	Number               string    `json:"number"`
	Code                 string    `json:"-"` // never serialized to clients
	Verified             bool      `json:"verified"`
	Attempts             int       `json:"attempts"`
	AllowedToRequestCode bool      `json:"allowedToRequestCode"`
	CreatedAt            time.Time `json:"createdAt"`
	ExpiresAt            time.Time `json:"expiresAt"`
	// NextCodeRequestAt is the earliest moment a fresh SendCode call may
	// succeed for this session. Until that instant SendCode returns
	// *RequestCodeRateLimitedError so the client can surface the
	// "may_request_sms"/"next_sms_seconds" hint to the user. Mirrors
	// Java's per-session rate-limit state.
	NextCodeRequestAt time.Time `json:"nextCodeRequestAt,omitempty"`
	// CodeRequests counts the number of SendCode invocations against this
	// session; the manager uses the count to compute the next allowed-at
	// and the captcha-escalation gate.
	CodeRequests int `json:"codeRequests,omitempty"`
	// CaptchaRequired is true when the session needs a successful captcha
	// submission before the next SendCode call may proceed. Escalation
	// fires automatically once CodeRequests crosses the threshold set on
	// ManagerConfig.CaptchaEscalationAfter. The PATCH session handler
	// clears the flag when a captcha verifies.
	CaptchaRequired bool `json:"captchaRequired,omitempty"`
}

// SendOption configures optional behavior for transport sending.
type SendOption func(*SendOptions)

// SendOptions holds the resolved send option values.
type SendOptions struct {
	Carrier string
}

// ApplySendOptions applies the given SendOption functions and returns the
// resolved options.
func ApplySendOptions(opts ...SendOption) SendOptions {
	var o SendOptions
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// WithCarrier specifies the mobile carrier for SMS-via-SMTP routing.
func WithCarrier(carrier string) SendOption {
	return func(o *SendOptions) {
		o.Carrier = carrier
	}
}
