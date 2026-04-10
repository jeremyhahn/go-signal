//go:build fido2

package config

import (
	"errors"
	"testing"
)

func TestFIDO2Config_Validate_Disabled(t *testing.T) {
	cfg := &FIDO2Config{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled FIDO2 should not error, got: %v", err)
	}
}

func TestFIDO2Config_Validate_DisabledEmptyFields(t *testing.T) {
	cfg := &FIDO2Config{
		Enabled: false,
		RPID:    "",
		RPName:  "",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled FIDO2 with empty fields should not error, got: %v", err)
	}
}

func TestFIDO2Config_Validate_MissingRPID(t *testing.T) {
	cfg := &FIDO2Config{
		Enabled:   true,
		RPID:      "",
		RPName:    "Signal",
		RPOrigins: []string{"https://signal.org"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for missing rpId")
	}
	var target *ConfigValidationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigValidationError, got %T", err)
	}
	if target.Field != "fido2.rpId" {
		t.Errorf("got field %q, want %q", target.Field, "fido2.rpId")
	}
}

func TestFIDO2Config_Validate_MissingRPName(t *testing.T) {
	cfg := &FIDO2Config{
		Enabled:   true,
		RPID:      "signal.org",
		RPName:    "",
		RPOrigins: []string{"https://signal.org"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for missing rpName")
	}
	var target *ConfigValidationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigValidationError, got %T", err)
	}
	if target.Field != "fido2.rpName" {
		t.Errorf("got field %q, want %q", target.Field, "fido2.rpName")
	}
}

func TestFIDO2Config_Validate_MissingRPOrigins(t *testing.T) {
	cfg := &FIDO2Config{
		Enabled:   true,
		RPID:      "signal.org",
		RPName:    "Signal",
		RPOrigins: nil,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for missing rpOrigins")
	}
	var target *ConfigValidationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigValidationError, got %T", err)
	}
	if target.Field != "fido2.rpOrigins" {
		t.Errorf("got field %q, want %q", target.Field, "fido2.rpOrigins")
	}
}

func TestFIDO2Config_Validate_EmptyRPOrigins(t *testing.T) {
	cfg := &FIDO2Config{
		Enabled:   true,
		RPID:      "signal.org",
		RPName:    "Signal",
		RPOrigins: []string{},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for empty rpOrigins")
	}
	var target *ConfigValidationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigValidationError, got %T", err)
	}
	if target.Field != "fido2.rpOrigins" {
		t.Errorf("got field %q, want %q", target.Field, "fido2.rpOrigins")
	}
}

func TestFIDO2Config_Validate_InvalidAttestation(t *testing.T) {
	cfg := &FIDO2Config{
		Enabled:     true,
		RPID:        "signal.org",
		RPName:      "Signal",
		RPOrigins:   []string{"https://signal.org"},
		Attestation: "invalid",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid attestation")
	}
	var target *ConfigValidationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigValidationError, got %T", err)
	}
	if target.Field != "fido2.attestation" {
		t.Errorf("got field %q, want %q", target.Field, "fido2.attestation")
	}
}

func TestFIDO2Config_Validate_InvalidUserVerification(t *testing.T) {
	cfg := &FIDO2Config{
		Enabled:          true,
		RPID:             "signal.org",
		RPName:           "Signal",
		RPOrigins:        []string{"https://signal.org"},
		Attestation:      "direct",
		UserVerification: "invalid",
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error for invalid userVerification")
	}
	var target *ConfigValidationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigValidationError, got %T", err)
	}
	if target.Field != "fido2.userVerification" {
		t.Errorf("got field %q, want %q", target.Field, "fido2.userVerification")
	}
}

func TestFIDO2Config_Validate_ValidAttestationValues(t *testing.T) {
	tests := []struct {
		name        string
		attestation string
	}{
		{"empty_string", ""},
		{"none", "none"},
		{"indirect", "indirect"},
		{"direct", "direct"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &FIDO2Config{
				Enabled:     true,
				RPID:        "signal.org",
				RPName:      "Signal",
				RPOrigins:   []string{"https://signal.org"},
				Attestation: tt.attestation,
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("unexpected error for attestation %q: %v", tt.attestation, err)
			}
		})
	}
}

func TestFIDO2Config_Validate_ValidUserVerificationValues(t *testing.T) {
	tests := []struct {
		name             string
		userVerification string
	}{
		{"empty_string", ""},
		{"required", "required"},
		{"preferred", "preferred"},
		{"discouraged", "discouraged"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &FIDO2Config{
				Enabled:          true,
				RPID:             "signal.org",
				RPName:           "Signal",
				RPOrigins:        []string{"https://signal.org"},
				UserVerification: tt.userVerification,
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("unexpected error for userVerification %q: %v", tt.userVerification, err)
			}
		})
	}
}

func TestFIDO2Config_Validate_FullyValid(t *testing.T) {
	cfg := &FIDO2Config{
		Enabled:          true,
		RPID:             "signal.org",
		RPName:           "Signal",
		RPOrigins:        []string{"https://signal.org", "https://app.signal.org"},
		Attestation:      "direct",
		UserVerification: "required",
		TimeoutSeconds:   120,
		RequireMFA:       true,
		AllowFIDO2Only:   true,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFIDO2Config_ApplyDefaults_AllEmpty(t *testing.T) {
	cfg := &FIDO2Config{}
	cfg.ApplyDefaults()

	if cfg.Attestation != "none" {
		t.Errorf("got attestation %q, want %q", cfg.Attestation, "none")
	}
	if cfg.UserVerification != "preferred" {
		t.Errorf("got userVerification %q, want %q", cfg.UserVerification, "preferred")
	}
	if cfg.TimeoutSeconds != 60 {
		t.Errorf("got timeoutSeconds %d, want 60", cfg.TimeoutSeconds)
	}
}

func TestFIDO2Config_ApplyDefaults_PreservesExistingValues(t *testing.T) {
	cfg := &FIDO2Config{
		Attestation:      "direct",
		UserVerification: "required",
		TimeoutSeconds:   120,
	}
	cfg.ApplyDefaults()

	if cfg.Attestation != "direct" {
		t.Errorf("got attestation %q, want %q", cfg.Attestation, "direct")
	}
	if cfg.UserVerification != "required" {
		t.Errorf("got userVerification %q, want %q", cfg.UserVerification, "required")
	}
	if cfg.TimeoutSeconds != 120 {
		t.Errorf("got timeoutSeconds %d, want 120", cfg.TimeoutSeconds)
	}
}

func TestFIDO2Config_ApplyDefaults_PartialOverride(t *testing.T) {
	cfg := &FIDO2Config{
		Attestation: "indirect",
	}
	cfg.ApplyDefaults()

	if cfg.Attestation != "indirect" {
		t.Errorf("got attestation %q, want %q", cfg.Attestation, "indirect")
	}
	if cfg.UserVerification != "preferred" {
		t.Errorf("got userVerification %q, want %q", cfg.UserVerification, "preferred")
	}
	if cfg.TimeoutSeconds != 60 {
		t.Errorf("got timeoutSeconds %d, want 60", cfg.TimeoutSeconds)
	}
}
