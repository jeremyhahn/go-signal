package captcha

import (
	"errors"
	"testing"
)

func TestChallengeFailedError_Error(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    string
	}{
		{"with_message", "bad token", "challenge failed: bad token"},
		{"empty_message", "", "challenge failed: "},
		{"long_message", "the provided CAPTCHA solution was incorrect", "challenge failed: the provided CAPTCHA solution was incorrect"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ChallengeFailedError{Message: tt.message}
			if got := e.Error(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestChallengeFailedError_TypeAssertion(t *testing.T) {
	var err error = &ChallengeFailedError{Message: "test"}
	var target *ChallengeFailedError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *ChallengeFailedError")
	}
	if target.Message != "test" {
		t.Errorf("got %q, want %q", target.Message, "test")
	}
}

func TestChallengeFailedError_ImplementsError(t *testing.T) {
	var _ error = &ChallengeFailedError{}
}

func TestInvalidChallengeTypeError_Error(t *testing.T) {
	tests := []struct {
		name     string
		typeName string
		want     string
	}{
		{"known_type", "unknown", "invalid challenge type: unknown"},
		{"empty_type", "", "invalid challenge type: "},
		{"arbitrary_type", "foobar", "invalid challenge type: foobar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &InvalidChallengeTypeError{Type: tt.typeName}
			if got := e.Error(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInvalidChallengeTypeError_TypeAssertion(t *testing.T) {
	var err error = &InvalidChallengeTypeError{Type: "xyz"}
	var target *InvalidChallengeTypeError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *InvalidChallengeTypeError")
	}
	if target.Type != "xyz" {
		t.Errorf("got %q, want %q", target.Type, "xyz")
	}
}

func TestInvalidChallengeTypeError_ImplementsError(t *testing.T) {
	var _ error = &InvalidChallengeTypeError{}
}

// --------------------------------------------------------------------------
// CaptchaVerificationFailedError
// --------------------------------------------------------------------------

func TestCaptchaVerificationFailedError_WithErrorCodes(t *testing.T) {
	e := &CaptchaVerificationFailedError{ErrorCodes: []string{"code-1", "code-2"}}
	got := e.Error()
	if got == "" {
		t.Fatal("expected non-empty error string")
	}
	// Must contain the error codes in the message.
	for _, code := range e.ErrorCodes {
		found := false
		for i := 0; i < len(got)-len(code)+1; i++ {
			if got[i:i+len(code)] == code {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("error string %q does not contain code %q", got, code)
		}
	}
}

func TestCaptchaVerificationFailedError_WithoutErrorCodes(t *testing.T) {
	e := &CaptchaVerificationFailedError{}
	got := e.Error()
	want := "captcha verification failed: score below threshold"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCaptchaVerificationFailedError_ImplementsError(t *testing.T) {
	var _ error = &CaptchaVerificationFailedError{}
}

func TestCaptchaVerificationFailedError_TypeAssertion(t *testing.T) {
	var err error = &CaptchaVerificationFailedError{ErrorCodes: []string{"x"}}
	var target *CaptchaVerificationFailedError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *CaptchaVerificationFailedError")
	}
}

// --------------------------------------------------------------------------
// CaptchaNetworkError
// --------------------------------------------------------------------------

func TestCaptchaNetworkError_Error(t *testing.T) {
	cause := errors.New("connection refused")
	e := &CaptchaNetworkError{Provider: "hcaptcha", Cause: cause}
	got := e.Error()
	want := "captcha network error (hcaptcha): connection refused"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCaptchaNetworkError_Unwrap(t *testing.T) {
	cause := errors.New("timeout")
	e := &CaptchaNetworkError{Provider: "recaptcha", Cause: cause}
	if !errors.Is(e, cause) {
		t.Error("errors.Is should find the wrapped cause")
	}
}

func TestCaptchaNetworkError_ImplementsError(t *testing.T) {
	var _ error = &CaptchaNetworkError{}
}

// --------------------------------------------------------------------------
// CaptchaParseError
// --------------------------------------------------------------------------

func TestCaptchaParseError_Error(t *testing.T) {
	cause := errors.New("unexpected token")
	e := &CaptchaParseError{Provider: "recaptcha", Cause: cause}
	got := e.Error()
	want := "captcha parse error (recaptcha): unexpected token"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCaptchaParseError_Unwrap(t *testing.T) {
	cause := errors.New("EOF")
	e := &CaptchaParseError{Provider: "hcaptcha", Cause: cause}
	if !errors.Is(e, cause) {
		t.Error("errors.Is should find the wrapped cause")
	}
}

func TestCaptchaParseError_ImplementsError(t *testing.T) {
	var _ error = &CaptchaParseError{}
}

// --------------------------------------------------------------------------
// HCaptchaConfigError
// --------------------------------------------------------------------------

func TestHCaptchaConfigError_Error(t *testing.T) {
	e := &HCaptchaConfigError{Message: "secretKey is required"}
	want := "hcaptcha config error: secretKey is required"
	if got := e.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHCaptchaConfigError_ImplementsError(t *testing.T) {
	var _ error = &HCaptchaConfigError{}
}

// --------------------------------------------------------------------------
// ReCAPTCHAConfigError
// --------------------------------------------------------------------------

func TestReCAPTCHAConfigError_Error(t *testing.T) {
	e := &ReCAPTCHAConfigError{Message: "secretKey is required"}
	want := "recaptcha config error: secretKey is required"
	if got := e.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReCAPTCHAConfigError_ImplementsError(t *testing.T) {
	var _ error = &ReCAPTCHAConfigError{}
}
