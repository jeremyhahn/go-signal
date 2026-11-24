//go:build smtp

package smtp

import (
	"context"
	"net/smtp"
	"strconv"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// TransportConfig configures the SMTP verification transport.
type TransportConfig struct {
	Host            string                // SMTP server hostname
	Port            int                   // SMTP server port
	Username        string                // SMTP authentication username
	Password        *secrets.SecureString // SMTP authentication password
	FromAddress     string                // sender email address
	UseTLS          bool                  // whether to use STARTTLS
	CarrierGateways map[string]string     // override default carrier gateways
	DefaultCarrier  string                // default carrier when none specified
}

// Transport sends verification codes via SMTP email-to-SMS gateways.
type Transport struct {
	config TransportConfig
}

var _ verification.VerificationTransport = (*Transport)(nil)

// NewTransport creates a new SMTP Transport.
func NewTransport(config TransportConfig) *Transport {
	return &Transport{config: config}
}

// SendCode delivers a verification code to the given destination phone number
// via an SMTP email-to-SMS gateway.
func (t *Transport) SendCode(_ context.Context, destination string, code string, opts ...verification.SendOption) error {
	resolved := verification.ApplySendOptions(opts...)

	carrier := resolved.Carrier
	if carrier == "" {
		carrier = t.config.DefaultCarrier
	}
	if carrier == "" {
		return &verification.CarrierNotFoundError{Carrier: ""}
	}

	gatewayDomain, ok := t.lookupGateway(carrier)
	if !ok {
		return &verification.CarrierNotFoundError{Carrier: carrier}
	}

	toAddr := FormatSMSAddress(destination, gatewayDomain)
	body := formatMessage(t.config.FromAddress, toAddr, code)
	addr := t.config.Host + ":" + strconv.Itoa(t.config.Port)

	password := ""
	if t.config.Password != nil {
		password = t.config.Password.Plaintext()
	}
	auth := smtp.PlainAuth("", t.config.Username, password, t.config.Host)

	if err := smtp.SendMail(addr, auth, t.config.FromAddress, []string{toAddr}, body); err != nil {
		return &verification.TransportError{
			Transport:   t.Name(),
			Destination: destination,
			Cause:       err,
		}
	}

	return nil
}

// Name returns the transport identifier.
func (t *Transport) Name() string {
	return "smtp"
}

// lookupGateway looks up the gateway domain for the given carrier, checking
// configured overrides first, then falling back to the built-in defaults.
func (t *Transport) lookupGateway(carrier string) (string, bool) {
	if t.config.CarrierGateways != nil {
		if gw, ok := t.config.CarrierGateways[carrier]; ok {
			return gw, true
		}
	}
	return GatewayForCarrier(carrier)
}

// formatMessage constructs the email body for an SMS verification message.
func formatMessage(from string, to string, code string) []byte {
	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: Signal Verification\r\n" +
		"\r\n" +
		"Your Signal verification code is: " + code + "\r\n"
	return []byte(msg)
}
