//go:build smtp

package smtp

import (
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/verification"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTransport(t *testing.T) {
	t.Parallel()

	password := secrets.NewSecureString("pass")
	defer password.Destroy()

	config := TransportConfig{
		Host:           "smtp.example.com",
		Port:           587,
		Username:       "user",
		Password:       password,
		FromAddress:    "verify@example.com",
		DefaultCarrier: "verizon",
	}
	transport := NewTransport(config)

	assert.NotNil(t, transport)
	assert.Equal(t, "smtp", transport.Name())
}

func TestTransport_Name(t *testing.T) {
	t.Parallel()

	transport := NewTransport(TransportConfig{})
	assert.Equal(t, "smtp", transport.Name())
}

func TestTransport_ImplementsInterface(t *testing.T) {
	t.Parallel()

	var _ verification.VerificationTransport = (*Transport)(nil)
}

func TestTransport_LookupGateway_Default(t *testing.T) {
	t.Parallel()

	transport := NewTransport(TransportConfig{})

	gw, ok := transport.lookupGateway("verizon")
	assert.True(t, ok)
	assert.Equal(t, "vtext.com", gw)
}

func TestTransport_LookupGateway_Override(t *testing.T) {
	t.Parallel()

	transport := NewTransport(TransportConfig{
		CarrierGateways: map[string]string{
			"custom": "sms.custom.com",
		},
	})

	gw, ok := transport.lookupGateway("custom")
	assert.True(t, ok)
	assert.Equal(t, "sms.custom.com", gw)
}

func TestTransport_LookupGateway_OverrideFallsBackToDefault(t *testing.T) {
	t.Parallel()

	transport := NewTransport(TransportConfig{
		CarrierGateways: map[string]string{
			"custom": "sms.custom.com",
		},
	})

	gw, ok := transport.lookupGateway("verizon")
	assert.True(t, ok)
	assert.Equal(t, "vtext.com", gw)
}

func TestTransport_LookupGateway_NotFound(t *testing.T) {
	t.Parallel()

	transport := NewTransport(TransportConfig{})

	_, ok := transport.lookupGateway("nonexistent")
	assert.False(t, ok)
}

func TestTransport_SendCode_NoCarrier(t *testing.T) {
	t.Parallel()

	transport := NewTransport(TransportConfig{})
	err := transport.SendCode(t.Context(), "+15551234567", "123456")
	require.Error(t, err)

	var carrierErr *verification.CarrierNotFoundError
	assert.ErrorAs(t, err, &carrierErr)
}

func TestTransport_SendCode_UnknownCarrier(t *testing.T) {
	t.Parallel()

	transport := NewTransport(TransportConfig{
		DefaultCarrier: "nonexistent",
	})
	err := transport.SendCode(t.Context(), "+15551234567", "123456")
	require.Error(t, err)

	var carrierErr *verification.CarrierNotFoundError
	assert.ErrorAs(t, err, &carrierErr)
	assert.Equal(t, "nonexistent", carrierErr.Carrier)
}

func TestTransport_SendCode_WithCarrierOption(t *testing.T) {
	t.Parallel()

	transport := NewTransport(TransportConfig{
		Host:        "localhost",
		Port:        25,
		FromAddress: "verify@example.com",
	})

	// This will fail at SMTP dial, but we verify the carrier option is resolved.
	err := transport.SendCode(t.Context(), "+15551234567", "123456", verification.WithCarrier("verizon"))
	require.Error(t, err)

	// Should be a transport error (SMTP failure), not a carrier error.
	var transportErr *verification.TransportError
	assert.ErrorAs(t, err, &transportErr)
	assert.Equal(t, "smtp", transportErr.Transport)
}

func TestTransport_SendCode_DefaultCarrierUsed(t *testing.T) {
	t.Parallel()

	transport := NewTransport(TransportConfig{
		Host:           "localhost",
		Port:           25,
		FromAddress:    "verify@example.com",
		DefaultCarrier: "att",
	})

	// Will fail at SMTP dial, but carrier should be resolved.
	err := transport.SendCode(t.Context(), "+15551234567", "123456")
	require.Error(t, err)

	var transportErr *verification.TransportError
	assert.ErrorAs(t, err, &transportErr)
}

func TestFormatMessage(t *testing.T) {
	t.Parallel()

	msg := formatMessage("from@example.com", "15551234567@vtext.com", "123456")
	expected := "From: from@example.com\r\n" +
		"To: 15551234567@vtext.com\r\n" +
		"Subject: Signal Verification\r\n" +
		"\r\n" +
		"Your Signal verification code is: 123456\r\n"

	assert.Equal(t, expected, string(msg))
}

func TestFormatMessage_DifferentCode(t *testing.T) {
	t.Parallel()

	msg := formatMessage("noreply@signal.org", "15559876543@txt.att.net", "987654")
	assert.Contains(t, string(msg), "Your Signal verification code is: 987654")
	assert.Contains(t, string(msg), "From: noreply@signal.org")
	assert.Contains(t, string(msg), "To: 15559876543@txt.att.net")
}
