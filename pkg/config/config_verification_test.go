package config

import (
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func TestVerificationConfig_ApplyDefaults_AllEmpty(t *testing.T) {
	cfg := &VerificationConfig{}
	cfg.ApplyDefaults()

	if cfg.CodeLength != 6 {
		t.Errorf("got codeLength %d, want 6", cfg.CodeLength)
	}
	if cfg.CodeTTLSeconds != 300 {
		t.Errorf("got codeTTLSeconds %d, want 300", cfg.CodeTTLSeconds)
	}
	if cfg.MaxAttempts != 3 {
		t.Errorf("got maxAttempts %d, want 3", cfg.MaxAttempts)
	}
	if cfg.Transport != "stub" {
		t.Errorf("got transport %q, want %q", cfg.Transport, "stub")
	}
}

func TestVerificationConfig_ApplyDefaults_PreservesExistingValues(t *testing.T) {
	cfg := &VerificationConfig{
		CodeLength:     8,
		CodeTTLSeconds: 600,
		MaxAttempts:    5,
		Transport:      "smtp",
	}
	cfg.ApplyDefaults()

	if cfg.CodeLength != 8 {
		t.Errorf("got codeLength %d, want 8", cfg.CodeLength)
	}
	if cfg.CodeTTLSeconds != 600 {
		t.Errorf("got codeTTLSeconds %d, want 600", cfg.CodeTTLSeconds)
	}
	if cfg.MaxAttempts != 5 {
		t.Errorf("got maxAttempts %d, want 5", cfg.MaxAttempts)
	}
	if cfg.Transport != "smtp" {
		t.Errorf("got transport %q, want %q", cfg.Transport, "smtp")
	}
}

func TestVerificationConfig_ApplyDefaults_PartialCodeLength(t *testing.T) {
	cfg := &VerificationConfig{
		CodeLength: 4,
	}
	cfg.ApplyDefaults()

	if cfg.CodeLength != 4 {
		t.Errorf("got codeLength %d, want 4", cfg.CodeLength)
	}
	if cfg.CodeTTLSeconds != 300 {
		t.Errorf("got codeTTLSeconds %d, want 300", cfg.CodeTTLSeconds)
	}
	if cfg.MaxAttempts != 3 {
		t.Errorf("got maxAttempts %d, want 3", cfg.MaxAttempts)
	}
	if cfg.Transport != "stub" {
		t.Errorf("got transport %q, want %q", cfg.Transport, "stub")
	}
}

func TestVerificationConfig_ApplyDefaults_PartialTransport(t *testing.T) {
	cfg := &VerificationConfig{
		Transport: "smtp",
	}
	cfg.ApplyDefaults()

	if cfg.CodeLength != 6 {
		t.Errorf("got codeLength %d, want 6", cfg.CodeLength)
	}
	if cfg.Transport != "smtp" {
		t.Errorf("got transport %q, want %q", cfg.Transport, "smtp")
	}
}

func TestVerificationConfig_SMTPConfig_Fields(t *testing.T) {
	smtpPassword := secrets.MustNewSecureString("secret")
	defer smtpPassword.Destroy()

	cfg := &VerificationConfig{
		Transport: "smtp",
		SMTP: SMTPConfig{
			Host:           "smtp.example.com",
			Port:           587,
			Username:       "user@example.com",
			Password:       smtpPassword,
			FromAddress:    "noreply@example.com",
			UseTLS:         true,
			DefaultCarrier: "att",
			CarrierGateways: map[string]string{
				"att":     "txt.att.net",
				"verizon": "vtext.com",
				"tmobile": "tmomail.net",
			},
		},
	}
	cfg.ApplyDefaults()

	if cfg.SMTP.Host != "smtp.example.com" {
		t.Errorf("got smtp host %q, want %q", cfg.SMTP.Host, "smtp.example.com")
	}
	if cfg.SMTP.Port != 587 {
		t.Errorf("got smtp port %d, want 587", cfg.SMTP.Port)
	}
	if cfg.SMTP.Username != "user@example.com" {
		t.Errorf("got smtp username %q", cfg.SMTP.Username)
	}
	if !cfg.SMTP.UseTLS {
		t.Error("expected smtp useTLS true")
	}
	if cfg.SMTP.DefaultCarrier != "att" {
		t.Errorf("got default carrier %q, want %q", cfg.SMTP.DefaultCarrier, "att")
	}
	if len(cfg.SMTP.CarrierGateways) != 3 {
		t.Errorf("got %d carrier gateways, want 3", len(cfg.SMTP.CarrierGateways))
	}
	if cfg.SMTP.CarrierGateways["att"] != "txt.att.net" {
		t.Errorf("got att gateway %q", cfg.SMTP.CarrierGateways["att"])
	}
	if cfg.SMTP.Password == nil || cfg.SMTP.Password.Plaintext() != "secret" {
		t.Errorf("got smtp password %v", cfg.SMTP.Password)
	}
}

func TestVerificationConfig_ApplyDefaults_PartialTTL(t *testing.T) {
	cfg := &VerificationConfig{
		CodeTTLSeconds: 120,
	}
	cfg.ApplyDefaults()

	if cfg.CodeTTLSeconds != 120 {
		t.Errorf("got codeTTLSeconds %d, want 120", cfg.CodeTTLSeconds)
	}
	if cfg.CodeLength != 6 {
		t.Errorf("got codeLength %d, want 6", cfg.CodeLength)
	}
}

func TestVerificationConfig_ApplyDefaults_PartialMaxAttempts(t *testing.T) {
	cfg := &VerificationConfig{
		MaxAttempts: 10,
	}
	cfg.ApplyDefaults()

	if cfg.MaxAttempts != 10 {
		t.Errorf("got maxAttempts %d, want 10", cfg.MaxAttempts)
	}
	if cfg.CodeLength != 6 {
		t.Errorf("got codeLength %d, want 6", cfg.CodeLength)
	}
}
