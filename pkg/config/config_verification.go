package config

import "github.com/jeremyhahn/go-signal/pkg/config/secrets"

// VerificationConfig holds verification transport settings.
type VerificationConfig struct {
	CodeLength     int        `yaml:"codeLength"`
	CodeTTLSeconds int        `yaml:"codeTTLSeconds"`
	MaxAttempts    int        `yaml:"maxAttempts"`
	Transport      string     `yaml:"transport"` // "smtp", "stub"
	SMTP           SMTPConfig `yaml:"smtp"`

	// FixedCode overrides the randomly generated verification code with a
	// static value. This is intended exclusively for integration testing with
	// the stub transport. It MUST be left empty in production configurations.
	FixedCode string `yaml:"fixedCode"`
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
