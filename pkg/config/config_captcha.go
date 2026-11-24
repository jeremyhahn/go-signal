package config

import "github.com/jeremyhahn/go-signal/pkg/config/secrets"

// CaptchaConfig holds CAPTCHA verification backend settings.
type CaptchaConfig struct {
	// Provider is "hcaptcha", "recaptcha" or "test" (default).
	Provider string `yaml:"provider"`

	// SecretKey authenticates calls to the CAPTCHA service; not needed for "test".
	SecretKey *secrets.SecureString `yaml:"secretKey"`

	// SiteKey is the public site key; not needed for "test".
	SiteKey string `yaml:"siteKey"`

	// ScoreThreshold is the minimum reCAPTCHA v3 score in [0, 1]; zero uses 0.5.
	ScoreThreshold float64 `yaml:"scoreThreshold"`

	// SiteKeysByAction maps an action ("challenge", "registration") to its lower-cased allowed site keys; empty accepts any.
	SiteKeysByAction map[string][]string `yaml:"siteKeysByAction"`
}

// ApplyDefaults fills in missing CaptchaConfig values with safe defaults.
func (c *CaptchaConfig) ApplyDefaults() {
	if c.Provider == "" {
		c.Provider = "test"
	}
}
