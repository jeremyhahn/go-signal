package factory

import (
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func testLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestBuild_Stub(t *testing.T) {
	for _, transport := range []string{"", "stub"} {
		tr, err := Build(config.VerificationConfig{Transport: transport}, testLogger())
		if err != nil {
			t.Fatalf("transport %q: unexpected error: %v", transport, err)
		}
		if tr == nil {
			t.Fatalf("transport %q: expected a transport, got nil", transport)
		}
	}
}

func TestBuild_TwilioSuccess(t *testing.T) {
	tr, err := Build(config.VerificationConfig{
		Transport: "twilio",
		Twilio: config.TwilioConfig{
			AccountSID:       "AC123",
			AuthToken:        secrets.MustNewSecureString("token"),
			VerifyServiceSID: "VA123",
			Channel:          "sms",
		},
	}, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected a twilio transport, got nil")
	}
}

func TestBuild_TwilioMissingCredentials(t *testing.T) {
	// NewTransport fails fast when required fields are missing, so Build must
	// surface that error rather than returning a non-functional transport.
	_, err := Build(config.VerificationConfig{Transport: "twilio"}, testLogger())
	if err == nil {
		t.Fatal("expected error for twilio transport with missing credentials")
	}
}

func TestBuild_UnsupportedTransport(t *testing.T) {
	_, err := Build(config.VerificationConfig{Transport: "carrier-pigeon"}, testLogger())
	if err == nil {
		t.Fatal("expected error for unsupported transport")
	}
}
