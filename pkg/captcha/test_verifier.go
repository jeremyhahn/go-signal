package captcha

import (
	"context"
	"strings"
)

const (
	// TestTokenPrefix is the prefix recognised by TestVerifier as a
	// universally-valid token. Any token beginning with this prefix is
	// accepted without appearing in the explicit valid-token set.
	TestTokenPrefix = "test-captcha-" // #nosec G101 -- not a credential, test token prefix for dev/integration
)

// TestVerifier is a CaptchaVerifier intended for integration testing and local
// development. It accepts tokens that either appear in a configured allow-set
// or carry the TestTokenPrefix prefix. All other tokens are rejected. It must
// never be used in production.
type TestVerifier struct {
	// validTokens is the set of explicitly accepted tokens in addition to
	// any token carrying TestTokenPrefix.
	validTokens map[string]struct{}
}

// TestVerifierConfig holds the configuration for a TestVerifier.
type TestVerifierConfig struct {
	// ValidTokens is the explicit set of tokens to accept. May be nil or
	// empty; in that case only the TestTokenPrefix prefix is honoured.
	ValidTokens []string
}

// NewTestVerifier constructs a TestVerifier from the given config.
func NewTestVerifier(cfg TestVerifierConfig) *TestVerifier {
	valid := make(map[string]struct{}, len(cfg.ValidTokens))
	for _, tok := range cfg.ValidTokens {
		valid[tok] = struct{}{}
	}
	return &TestVerifier{validTokens: valid}
}

// Verify returns a successful VerifyResult when the token is in the explicit
// valid-token set or begins with TestTokenPrefix. Any other token returns a
// non-successful result. Verify never returns a non-nil error.
func (v *TestVerifier) Verify(_ context.Context, token string, _ string, _ string) (*VerifyResult, error) {
	if strings.HasPrefix(token, TestTokenPrefix) {
		return &VerifyResult{Success: true, Score: 1.0}, nil
	}
	if _, ok := v.validTokens[token]; ok {
		return &VerifyResult{Success: true, Score: 1.0}, nil
	}
	return &VerifyResult{
		Success:    false,
		ErrorCodes: []string{"invalid-input-response"},
	}, nil
}
