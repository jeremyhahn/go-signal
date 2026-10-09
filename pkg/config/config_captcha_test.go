package config

import (
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// --------------------------------------------------------------------------
// CaptchaConfig.ApplyDefaults
// --------------------------------------------------------------------------

func TestCaptchaConfig_ApplyDefaults_EmptyProviderBecomesTest(t *testing.T) {
	var c CaptchaConfig
	c.ApplyDefaults()
	if c.Provider != "test" {
		t.Errorf("got provider %q, want %q", c.Provider, "test")
	}
}

func TestCaptchaConfig_ApplyDefaults_PreservesExistingProvider(t *testing.T) {
	c := CaptchaConfig{Provider: "hcaptcha"}
	c.ApplyDefaults()
	if c.Provider != "hcaptcha" {
		t.Errorf("got provider %q, want %q", c.Provider, "hcaptcha")
	}
}

func TestCaptchaConfig_ApplyDefaults_PreservesRecaptchaProvider(t *testing.T) {
	c := CaptchaConfig{Provider: "recaptcha"}
	c.ApplyDefaults()
	if c.Provider != "recaptcha" {
		t.Errorf("got provider %q, want %q", c.Provider, "recaptcha")
	}
}

// --------------------------------------------------------------------------
// CaptchaConfig fields
// --------------------------------------------------------------------------

func TestCaptchaConfig_ZeroValue(t *testing.T) {
	var c CaptchaConfig
	if c.Provider != "" {
		t.Errorf("expected empty provider, got %q", c.Provider)
	}
	if c.SecretKey != nil {
		t.Errorf("expected nil SecretKey, got %v", c.SecretKey)
	}
	if c.SiteKey != "" {
		t.Errorf("expected empty SiteKey, got %q", c.SiteKey)
	}
	if c.ScoreThreshold != 0 {
		t.Errorf("expected 0 ScoreThreshold, got %v", c.ScoreThreshold)
	}
}

func TestCaptchaConfig_Fields(t *testing.T) {
	c := CaptchaConfig{
		Provider:       "hcaptcha",
		SecretKey:      secrets.MustNewSecureString(t.Context(), "my-secret"),
		SiteKey:        "my-site",
		ScoreThreshold: 0.7,
	}
	if c.Provider != "hcaptcha" {
		t.Errorf("got %q, want %q", c.Provider, "hcaptcha")
	}
	if c.SecretKey == nil || c.SecretKey.Plaintext(t.Context()) != "my-secret" {
		t.Errorf("got SecretKey %v, want plaintext %q", c.SecretKey, "my-secret")
	}
	if c.SiteKey != "my-site" {
		t.Errorf("got %q, want %q", c.SiteKey, "my-site")
	}
	if c.ScoreThreshold != 0.7 {
		t.Errorf("got %v, want 0.7", c.ScoreThreshold)
	}
}

// --------------------------------------------------------------------------
// Config.Captcha YAML loading
// --------------------------------------------------------------------------

func TestLoad_CaptchaConfig(t *testing.T) {
	yaml := validYAML() + `
captcha:
  provider: "hcaptcha"
  secretKey: "s3cr3t"
  siteKey: "public-site-key"
  scoreThreshold: 0.5
`
	path := writeYAML(t, yaml)
	cfg, err := Load(t.Context(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Captcha.Provider != "hcaptcha" {
		t.Errorf("got provider %q, want %q", cfg.Captcha.Provider, "hcaptcha")
	}
	if cfg.Captcha.SecretKey == nil || cfg.Captcha.SecretKey.Plaintext(t.Context()) != "s3cr3t" {
		t.Errorf("got secretKey %v, want plaintext %q", cfg.Captcha.SecretKey, "s3cr3t")
	}
	if cfg.Captcha.SiteKey != "public-site-key" {
		t.Errorf("got siteKey %q, want %q", cfg.Captcha.SiteKey, "public-site-key")
	}
	if cfg.Captcha.ScoreThreshold != 0.5 {
		t.Errorf("got scoreThreshold %v, want 0.5", cfg.Captcha.ScoreThreshold)
	}
}

func TestLoad_CaptchaConfig_Defaults(t *testing.T) {
	// Omitting captcha section from YAML: all fields should be zero/empty.
	path := writeYAML(t, validYAML())
	cfg, err := Load(t.Context(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Captcha.Provider != "" {
		t.Errorf("expected empty provider without YAML captcha section, got %q", cfg.Captcha.Provider)
	}
}

func TestLoad_CaptchaConfig_RecaptchaProvider(t *testing.T) {
	yaml := validYAML() + `
captcha:
  provider: "recaptcha"
  secretKey: "recaptcha-secret"
  scoreThreshold: 0.6
`
	path := writeYAML(t, yaml)
	cfg, err := Load(t.Context(), path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Captcha.Provider != "recaptcha" {
		t.Errorf("got provider %q, want %q", cfg.Captcha.Provider, "recaptcha")
	}
	if cfg.Captcha.ScoreThreshold != 0.6 {
		t.Errorf("got scoreThreshold %v, want 0.6", cfg.Captcha.ScoreThreshold)
	}
}
