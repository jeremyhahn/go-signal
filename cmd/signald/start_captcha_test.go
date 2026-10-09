package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// testCaptchaToken builds a submission in the dotted format the Checker
// requires: provider.sitekey.action.token.
func testCaptchaToken(t *testing.T) string {
	t.Helper()
	return "test.testkey.challenge." + captcha.TestTokenPrefix + "solution"
}

func TestBuildCaptchaChecker_TestProviderNeedsNoSecret(t *testing.T) {
	checker, err := buildCaptchaChecker(t.Context(), config.CaptchaConfig{Provider: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checker == nil {
		t.Fatal("expected a Checker for provider \"test\", got nil")
	}

	assess, err := checker.Verify(context.Background(), captcha.ActionChallenge, testCaptchaToken(t), "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !assess.Accepted() {
		t.Error("expected the test verifier to accept a test-prefixed token")
	}
}

// A token without the test prefix must still be rejected — the test provider
// accepts a known prefix, not everything.
func TestBuildCaptchaChecker_TestProviderRejectsUnknownToken(t *testing.T) {
	checker, err := buildCaptchaChecker(t.Context(), config.CaptchaConfig{Provider: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assess, err := checker.Verify(context.Background(), captcha.ActionChallenge, "test.testkey.challenge.bogus", "")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if assess.Accepted() {
		t.Error("expected the test verifier to reject a token without the test prefix")
	}
}

// No provider named yields no Checker; the REST layer turns that into a 503
// rather than accepting an unverifiable token.
func TestBuildCaptchaChecker_NoProviderYieldsNilChecker(t *testing.T) {
	checker, err := buildCaptchaChecker(t.Context(), config.CaptchaConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checker != nil {
		t.Errorf("expected nil Checker with no provider configured, got %#v", checker)
	}
}

func TestBuildCaptchaChecker_UnknownProviderIsAStartupError(t *testing.T) {
	secret, err := secrets.NewSecureString(t.Context(), "s3cret")
	if err != nil {
		t.Fatalf("NewSecureString: %v", err)
	}
	defer secret.Destroy()

	if _, err := buildCaptchaChecker(t.Context(), config.CaptchaConfig{
		Provider:  "nonesuch",
		SecretKey: secret,
	}); err == nil {
		t.Error("expected an error for an unknown captcha provider")
	}
}

// The test provider must never reach a production deployment. The gate lives
// in validateProduction; this asserts it actually refuses the combination
// buildCaptchaChecker would otherwise happily wire up.
//
// The port and storage backend are set so Validate reaches validateProduction
// at all — without them it returns early on an unrelated field, and the
// assertion below would pass without testing anything.
func TestProductionConfigRejectsTestCaptchaProvider(t *testing.T) {
	cfg := &config.Config{Mode: "production"}
	cfg.Server.HTTPPort = 8080
	cfg.Storage.Backend = "postgres"
	cfg.Captcha.Provider = "test"

	err := cfg.Validate(t.Context())

	var prodErr *config.ProductionValidationError
	if !errors.As(err, &prodErr) {
		t.Fatalf("expected *ProductionValidationError, got %#v", err)
	}
	if !slices.ContainsFunc(prodErr.Violations, func(v string) bool {
		return strings.Contains(v, "captcha.provider")
	}) {
		t.Errorf("expected a captcha.provider violation, got: %v", prodErr.Violations)
	}
}
