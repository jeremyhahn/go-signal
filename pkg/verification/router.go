package verification

import (
	"context"
	"errors"
	"strings"
)

// RouterTransport sends '+' destinations to SMS and '@' destinations to Email; an unconfigured channel returns ErrChannelNotConfigured.
type RouterTransport struct {
	SMS   VerificationTransport
	Email VerificationTransport
}

var _ VerificationTransport = (*RouterTransport)(nil)

// ErrChannelNotConfigured is returned when a destination's resolved channel
// has no transport configured.
var ErrChannelNotConfigured = errors.New("verification: destination channel not configured")

// Name returns "router" so logs distinguish routed sends from leaf transports.
func (r *RouterTransport) Name() string { return "router" }

// SendCode dispatches the call to the appropriate leg.
func (r *RouterTransport) SendCode(ctx context.Context, destination, code string, opts ...SendOption) error {
	t, err := r.transportFor(destination)
	if err != nil {
		return err
	}
	return t.SendCode(ctx, destination, code, opts...)
}

// transportFor picks email for '@' destinations and SMS otherwise.
func (r *RouterTransport) transportFor(destination string) (VerificationTransport, error) {
	switch DestinationChannel(destination) {
	case ChannelEmail:
		if r.Email == nil {
			return nil, ErrChannelNotConfigured
		}
		return r.Email, nil
	default:
		if r.SMS == nil {
			return nil, ErrChannelNotConfigured
		}
		return r.SMS, nil
	}
}

// Channel identifies a verification delivery channel.
type Channel int

const (
	// ChannelSMS routes to a phone-number SMS transport (Twilio, SMTP-to-SMS).
	ChannelSMS Channel = iota
	// ChannelEmail routes to an email transport (SES, SMTP).
	ChannelEmail
)

// DestinationChannel classifies a destination string by shape.
func DestinationChannel(destination string) Channel {
	if strings.Contains(destination, "@") {
		return ChannelEmail
	}
	return ChannelSMS
}
