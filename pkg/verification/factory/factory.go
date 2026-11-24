// Package factory builds the verification transport from configuration, separate from pkg/verification to avoid an import cycle.
package factory

import (
	"fmt"
	"log/slog"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/verification"
	"github.com/jeremyhahn/go-signal/pkg/verification/twilio"
)

// Build returns the transport for vc.Transport: "" or "stub" (logs the code, development only) or "twilio".
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
