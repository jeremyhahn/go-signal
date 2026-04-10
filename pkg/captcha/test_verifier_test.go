package captcha

import (
	"context"
	"testing"
)

// --------------------------------------------------------------------------
// NewTestVerifier construction
// --------------------------------------------------------------------------

func TestNewTestVerifier_NotNil(t *testing.T) {
	v := NewTestVerifier(TestVerifierConfig{})
	if v == nil {
		t.Fatal("expected non-nil verifier")
	}
}

func TestNewTestVerifier_WithValidTokens(t *testing.T) {
	v := NewTestVerifier(TestVerifierConfig{
		ValidTokens: []string{"tok-a", "tok-b"},
	})
	if len(v.validTokens) != 2 {
		t.Errorf("got %d valid tokens, want 2", len(v.validTokens))
	}
}

func TestNewTestVerifier_NilValidTokens(t *testing.T) {
	v := NewTestVerifier(TestVerifierConfig{ValidTokens: nil})
	if v == nil {
		t.Fatal("expected non-nil verifier")
	}
}

// --------------------------------------------------------------------------
// TestVerifier.Verify — prefix-based acceptance
// --------------------------------------------------------------------------

func TestTestVerifier_Verify_AcceptsPrefixToken(t *testing.T) {
	v := NewTestVerifier(TestVerifierConfig{})
	res, err := v.Verify(context.Background(), TestTokenPrefix+"anything", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Error("expected Success true for prefix token")
	}
	if res.Score != 1.0 {
		t.Errorf("got Score %v, want 1.0", res.Score)
	}
}

func TestTestVerifier_Verify_AcceptsPrefixTokenVariants(t *testing.T) {
	v := NewTestVerifier(TestVerifierConfig{})
	tokens := []string{
		TestTokenPrefix,
		TestTokenPrefix + "a",
		TestTokenPrefix + "some-long-value-123",
	}
	for _, tok := range tokens {
		res, err := v.Verify(context.Background(), tok, "", "")
		if err != nil {
			t.Fatalf("unexpected error for token %q: %v", tok, err)
		}
		if !res.Success {
			t.Errorf("expected Success true for token %q", tok)
		}
	}
}

// --------------------------------------------------------------------------
// TestVerifier.Verify — explicit valid-token set
// --------------------------------------------------------------------------

func TestTestVerifier_Verify_AcceptsExplicitToken(t *testing.T) {
	v := NewTestVerifier(TestVerifierConfig{ValidTokens: []string{"my-integration-token"}})
	res, err := v.Verify(context.Background(), "my-integration-token", "1.2.3.4", "site")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Success {
		t.Error("expected Success true for explicit token")
	}
	if res.Score != 1.0 {
		t.Errorf("got Score %v, want 1.0", res.Score)
	}
}

func TestTestVerifier_Verify_AcceptsMultipleExplicitTokens(t *testing.T) {
	valid := []string{"tok-1", "tok-2", "tok-3"}
	v := NewTestVerifier(TestVerifierConfig{ValidTokens: valid})
	for _, tok := range valid {
		res, err := v.Verify(context.Background(), tok, "", "")
		if err != nil {
			t.Fatalf("unexpected error for token %q: %v", tok, err)
		}
		if !res.Success {
			t.Errorf("expected Success true for token %q", tok)
		}
	}
}

// --------------------------------------------------------------------------
// TestVerifier.Verify — rejection
// --------------------------------------------------------------------------

func TestTestVerifier_Verify_RejectsUnknownToken(t *testing.T) {
	v := NewTestVerifier(TestVerifierConfig{})
	res, err := v.Verify(context.Background(), "random-token", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected Success false for unknown token")
	}
	if len(res.ErrorCodes) == 0 {
		t.Fatal("expected non-empty ErrorCodes on rejection")
	}
}

func TestTestVerifier_Verify_RejectsEmptyToken(t *testing.T) {
	v := NewTestVerifier(TestVerifierConfig{})
	res, err := v.Verify(context.Background(), "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected Success false for empty token")
	}
}

func TestTestVerifier_Verify_RejectsPartialPrefix(t *testing.T) {
	// A token that merely contains the prefix but doesn't start with it.
	v := NewTestVerifier(TestVerifierConfig{})
	res, err := v.Verify(context.Background(), "prefix-"+TestTokenPrefix, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected Success false for token with prefix in the middle")
	}
}

func TestTestVerifier_Verify_RejectsTokenNotInSet(t *testing.T) {
	v := NewTestVerifier(TestVerifierConfig{ValidTokens: []string{"allowed"}})
	res, err := v.Verify(context.Background(), "not-allowed", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Error("expected Success false for token not in allow-set")
	}
}

// --------------------------------------------------------------------------
// TestVerifier.Verify — never errors
// --------------------------------------------------------------------------

func TestTestVerifier_Verify_NeverReturnsError(t *testing.T) {
	v := NewTestVerifier(TestVerifierConfig{})
	tokens := []string{"", "bad", TestTokenPrefix + "ok", "explicit"}
	for _, tok := range tokens {
		_, err := v.Verify(context.Background(), tok, "", "")
		if err != nil {
			t.Errorf("unexpected error for token %q: %v", tok, err)
		}
	}
}

// --------------------------------------------------------------------------
// TestTokenPrefix constant
// --------------------------------------------------------------------------

func TestTestTokenPrefix_Value(t *testing.T) {
	if TestTokenPrefix != "test-captcha-" {
		t.Errorf("unexpected TestTokenPrefix value: %q", TestTokenPrefix)
	}
}
