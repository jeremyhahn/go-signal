package config

import "github.com/jeremyhahn/go-signal/pkg/config/secrets"

// CaptchaConfig holds CAPTCHA verification backend settings.
type CaptchaConfig struct {
	// Provider selects the CAPTCHA backend.
	// Accepted values: "hcaptcha", "recaptcha", "test".
	// Defaults to "test" when empty.
	Provider string `yaml:"provider"`

	// SecretKey is the server-side secret used to authenticate API calls to
	// the upstream CAPTCHA service. Not required for the "test" provider.
	SecretKey *secrets.SecureString `yaml:"secretKey"`

	// SiteKey is the public site key configured in the CAPTCHA dashboard.
	// It is forwarded to verifiers that require it. Not required for the
	// "test" provider.
	SiteKey string `yaml:"siteKey"`

	// ScoreThreshold is the minimum reCAPTCHA v3 score required to accept a
	// token. Values must be in the range [0.0, 1.0]. A zero value causes the
	// manager to use its built-in default (0.5). Not applicable to hCaptcha
	// or the test provider which do not emit scores.
	ScoreThreshold float64 `yaml:"scoreThreshold"`

	// SiteKeysByAction is the per-action allowlist enforced by the Checker
	// (Phase 3.3). Keys are action names ("challenge", "registration");
	// values are the lower-cased site keys accepted for that action. When
	// empty, the verifier accepts any site key (legacy behavior).
	//
	// Example:
	//
	//   siteKeysByAction:
	//     registration: ["abc-prod", "def-fallback"]
	//     challenge:    ["abc-prod"]
	SiteKeysByAction map[string][]string `yaml:"siteKeysByAction"`
}

// ApplyDefaults fills in missing CaptchaConfig values with safe defaults.
func (c *CaptchaConfig) ApplyDefaults() {
	if c.Provider == "" {
		c.Provider = "test"
	}
}
