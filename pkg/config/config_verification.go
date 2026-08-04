package config

import "github.com/jeremyhahn/go-signal/pkg/config/secrets"

// VerificationConfig holds verification transport settings.
type VerificationConfig struct {
	CodeLength     int          `yaml:"codeLength"`
	CodeTTLSeconds int          `yaml:"codeTTLSeconds"`
	MaxAttempts    int          `yaml:"maxAttempts"`
	Transport      string       `yaml:"transport"` // "twilio", "smtp", "stub"
	SMTP           SMTPConfig   `yaml:"smtp"`
	Twilio         TwilioConfig `yaml:"twilio"`

	// FixedCode overrides the randomly generated verification code with a
	// static value. This is intended exclusively for integration testing with
	// the stub transport. It MUST be left empty in production configurations.
	FixedCode string `yaml:"fixedCode"`

	// RemoteAddr is the gRPC host:port of an external registration-service
	// binary. When non-empty, signald opens a gRPC channel to that address
	// and the verification subsystem runs as a thin client; the local
	// session store and transport are NOT instantiated. When empty,
	// signald embeds the verification stack in-process (monolithic
	// topology). The chat-server captcha gate runs on the signald side
	// either way; see pkg/registration/sessionshim.
	RemoteAddr string `yaml:"remoteAddr"`

	// RemoteInsecure permits a plaintext gRPC channel to RemoteAddr.
	// Required for development / docker-compose; production deployments
	// must leave this false and supply mTLS via dial options that are
	// wired through the binary entry-point (registrationServiceDialOptions
	// in cmd/signald/start.go).
	RemoteInsecure bool `yaml:"remoteInsecure"`

	// GRPCListen is the host:port the standalone registration-service
	// binary binds its gRPC listener to. Empty means "use the default"
	// at the binary entry point (0.0.0.0:8090). Only consumed by
	// cmd/registration-service; signald ignores this field.
	GRPCListen string `yaml:"grpcListen"`
}

// SMTPConfig holds SMTP transport settings for SMS-via-email verification.
type SMTPConfig struct {
	Host            string                `yaml:"host"`
	Port            int                   `yaml:"port"`
	Username        string                `yaml:"username"`
	Password        *secrets.SecureString `yaml:"password"`
	FromAddress     string                `yaml:"fromAddress"`
	UseTLS          bool                  `yaml:"useTLS"`
	DefaultCarrier  string                `yaml:"defaultCarrier"`
	CarrierGateways map[string]string     `yaml:"carrierGateways"`
}

// TwilioConfig holds Twilio Verify transport settings. Twilio Verify
// generates and delivers the code itself (the server never sees or sets it),
// which is why no code is passed through.
type TwilioConfig struct {
	// AccountSID is the Twilio account SID (HTTP Basic username).
	AccountSID string `yaml:"accountSid"`
	// AuthToken is the Twilio auth token (HTTP Basic password).
	AuthToken *secrets.SecureString `yaml:"authToken"`
	// VerifyServiceSID is the Twilio Verify Service SID.
	VerifyServiceSID string `yaml:"verifyServiceSid"`
	// Channel selects the delivery channel: "sms" (default), "call", or
	// "whatsapp".
	Channel string `yaml:"channel"`
}

// VerificationDefaults applies default values to a VerificationConfig.
func (c *VerificationConfig) ApplyDefaults() {
	if c.CodeLength == 0 {
		c.CodeLength = 6
	}
	if c.CodeTTLSeconds == 0 {
		c.CodeTTLSeconds = 300
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 3
	}
	if c.Transport == "" {
		c.Transport = "stub"
	}
}
