// Package factory builds a verification transport from configuration. It
// lives in its own package because pkg/verification cannot import the
// concrete transports (e.g. twilio imports pkg/verification, which would
// create an import cycle). Both cmd/signald (monolithic mode) and
// cmd/registration-service construct their transport through Build so the
// transport-selection logic lives in exactly one place.
package factory

import (
	"fmt"
	"log/slog"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/verification"
	"github.com/jeremyhahn/go-signal/pkg/verification/twilio"
)

// Build returns the verification transport named by vc.Transport.
//
//   - "" / "stub": the development stub (logs the code; never delivers it).
//   - "twilio":    the Twilio Verify transport (production).
//
// The stub is rejected by the production config gate
// (config.validateProduction), so reaching it implies development mode.
func Build(vc config.VerificationConfig, logger *slog.Logger) (verification.VerificationTransport, error) {
	switch vc.Transport {
	case "", "stub":
		return verification.NewStubTransport(logger), nil
	case "twilio":
		return twilio.NewTransport(twilio.Config{
			AccountSID: vc.Twilio.AccountSID,
			AuthToken:  vc.Twilio.AuthToken,
			ServiceSID: vc.Twilio.VerifyServiceSID,
			Channel:    vc.Twilio.Channel,
		})
	default:
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("unsupported verification transport: %q", vc.Transport))
	}
}
