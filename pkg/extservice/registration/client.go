// Package registration is the typed client surface for the
// registration-service. signald talks to registration-service through
// this interface and never reaches for a *core.Service directly. Two
// implementations live alongside it:
//
//   - subpackage inprocess  — wraps a local *core.Service so unit tests
//     and monolithic deployments do not need a network hop.
//   - subpackage grpcclient — opens a gRPC channel to a remote
//     registration-service binary defined by
//     RegistrationService.proto.
//
// The interface intentionally does NOT carry captcha verification.
// Captcha state lives on the chat-server side (see
// pkg/registration/sessionshim) per the Java reference split: the
// registration-service is unaware of captcha and only handles session
// state + transport delivery + rate-limit bookkeeping.
package registration

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// Client is the surface signald exposes for talking to the
// registration-service. Returning *verification.VerificationSession +
// the typed *verification.* errors directly keeps the REST handler
// error-mapping code identical to the pre-split implementation; the
// gRPC adapter is responsible for translating proto error envelopes
// back into those typed errors so callers see one consistent contract
// regardless of transport.
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
