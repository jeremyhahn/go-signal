package verification

import "context"

// VerificationTransport sends verification codes to destinations.
type VerificationTransport interface {
	// SendCode delivers a verification code to the given destination.
	SendCode(ctx context.Context, destination string, code string, opts ...SendOption) error

	// Name returns the transport identifier (e.g. "smtp", "twilio").
	Name() string
}
