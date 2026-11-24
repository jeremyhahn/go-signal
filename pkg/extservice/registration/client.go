// Package registration is signald's client for the registration-service: inprocess wraps a local *core.Service, grpcclient dials a remote one. Captcha stays on the chat-server side.
package registration

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// Client returns the typed verification errors for every transport, so REST error mapping is the same either way.
type Client interface {
	// CreateSession opens a new verification session for the supplied
	// E.164 number. Returns *verification.SessionLimitExceededError
	// when the server-wide cap is reached.
	CreateSession(ctx context.Context, number string) (*verification.VerificationSession, error)

	// GetSession retrieves a session by ID. Returns
	// *verification.SessionNotFoundError when the session has expired
	// or never existed.
	GetSession(ctx context.Context, sessionID string) (*verification.VerificationSession, error)

	// SendCode generates and delivers a fresh verification code.
	// Returns *verification.RequestCodeRateLimitedError when the
	// per-session cooldown has not elapsed.
	SendCode(ctx context.Context, sessionID string) (*verification.VerificationSession, error)

	// SubmitCode validates a user-supplied verification code. Returns
	// *verification.InvalidCodeError on mismatch, advancing the
	// attempts counter so the rate-limit cap can fire later.
	SubmitCode(ctx context.Context, sessionID, code string) (*verification.VerificationSession, error)

	// Close releases any client-side resources (gRPC connections,
	// goroutines). The in-process adapter is a no-op.
	Close() error
}
