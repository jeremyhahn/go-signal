package verification

import (
	"context"
	"log/slog"
)

// StubTransport implements VerificationTransport by logging codes instead of
// delivering them. It is used in development and testing when no real SMS/email
// transport is configured.
type StubTransport struct {
	logger *slog.Logger
}

// NewStubTransport creates a new StubTransport that logs codes to the given logger.
func NewStubTransport(logger *slog.Logger) *StubTransport {
	return &StubTransport{logger: logger}
}

// SendCode logs the verification code instead of delivering it.
func (t *StubTransport) SendCode(_ context.Context, destination string, code string, _ ...SendOption) error {
	t.logger.Info("stub verification code",
		slog.String("destination", redactDestination(destination)),
		slog.String("code", code))
	return nil
}

// Name returns the transport identifier.
func (t *StubTransport) Name() string {
	return "stub"
}

// redactDestination partially redacts a phone number for logging.
func redactDestination(dest string) string {
	if len(dest) < 5 {
		return "****"
	}
	return dest[:4] + "****"
}
