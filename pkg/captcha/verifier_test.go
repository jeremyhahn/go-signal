package captcha

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// --------------------------------------------------------------------------
// VerifyResult
// --------------------------------------------------------------------------

func TestVerifyResult_ZeroValue(t *testing.T) {
	var r VerifyResult
	if r.Success {
		t.Error("zero-value Success should be false")
	}
	if r.Score != 0 {
		t.Errorf("zero-value Score should be 0, got %v", r.Score)
	}
	if r.Action != "" {
		t.Errorf("zero-value Action should be empty, got %q", r.Action)
	}
	if r.Hostname != "" {
		t.Errorf("zero-value Hostname should be empty, got %q", r.Hostname)
	}
	if len(r.ErrorCodes) != 0 {
		t.Errorf("zero-value ErrorCodes should be empty, got %v", r.ErrorCodes)
	}
}

func TestVerifyResult_SuccessFields(t *testing.T) {
	r := VerifyResult{
		Success:  true,
		Score:    0.9,
		Action:   "register",
		Hostname: "example.com",
	}
	if !r.Success {
		t.Error("expected Success true")
	}
	if r.Score != 0.9 {
		t.Errorf("got Score %v, want 0.9", r.Score)
	}
	if r.Action != "register" {
		t.Errorf("got Action %q, want %q", r.Action, "register")
	}
	if r.Hostname != "example.com" {
		t.Errorf("got Hostname %q, want %q", r.Hostname, "example.com")
	}
}

func TestVerifyResult_ErrorCodes(t *testing.T) {
	r := VerifyResult{
		Success:    false,
		ErrorCodes: []string{"invalid-input-response", "missing-input-secret"},
	}
	if r.Success {
		t.Error("expected Success false")
	}
	if len(r.ErrorCodes) != 2 {
		t.Errorf("got %d error codes, want 2", len(r.ErrorCodes))
	}
}

// --------------------------------------------------------------------------
// CaptchaVerifier interface compliance
// --------------------------------------------------------------------------

func TestCaptchaVerifier_InterfaceCompliance(t *testing.T) {
	var _ CaptchaVerifier = &errVerifier{}
	var _ CaptchaVerifier = &scoreVerifier{}
	var _ CaptchaVerifier = NewTestVerifier(TestVerifierConfig{})
}

// Ensure HCaptchaVerifier and ReCAPTCHAVerifier satisfy the interface when
// constructed successfully.
func TestCaptchaVerifier_HCaptchaImplementsInterface(t *testing.T) {
	v, err := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{SecretKey: secrets.MustNewSecureString(t.Context(), "dummy")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var _ CaptchaVerifier = v
}

func TestCaptchaVerifier_ReCAPTCHAImplementsInterface(t *testing.T) {
	v, err := NewReCAPTCHAVerifier(t.Context(), ReCAPTCHAConfig{SecretKey: secrets.MustNewSecureString(t.Context(), "dummy")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var _ CaptchaVerifier = v
}

// --------------------------------------------------------------------------
// errVerifier / scoreVerifier (test helpers used by multiple test files)
// These are defined in manager_test.go; this file only verifies behaviour.
// --------------------------------------------------------------------------

func TestErrVerifier_AlwaysErrors(t *testing.T) {
	sentinel := &CaptchaNetworkError{Provider: "test", Cause: context.Canceled}
	v := &errVerifier{err: sentinel}
	_, err := v.Verify(context.Background(), "tok", "1.2.3.4", "site")
	if err != sentinel {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

func TestScoreVerifier_ReturnsConfiguredScore(t *testing.T) {
	v := &scoreVerifier{score: 0.75}
	res, err := v.Verify(context.Background(), "tok", "1.2.3.4", "site")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Error("expected Success true")
	}
	if res.Score != 0.75 {
		t.Errorf("got Score %v, want 0.75", res.Score)
	}
}
