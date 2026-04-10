package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// --------------------------------------------------------------------------
// NewReCAPTCHAVerifier construction
// --------------------------------------------------------------------------

func TestNewReCAPTCHAVerifier_Success(t *testing.T) {
	v, err := NewReCAPTCHAVerifier(ReCAPTCHAConfig{SecretKey: secrets.NewSecureString("secret")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil verifier")
	}
}

func TestNewReCAPTCHAVerifier_EmptySecretKey(t *testing.T) {
	_, err := NewReCAPTCHAVerifier(ReCAPTCHAConfig{})
	if err == nil {
		t.Fatal("expected error for empty secret key")
	}
	var target *ReCAPTCHAConfigError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ReCAPTCHAConfigError, got %T", err)
	}
}

func TestNewReCAPTCHAVerifier_UsesDefaultEndpoint(t *testing.T) {
	v, err := NewReCAPTCHAVerifier(ReCAPTCHAConfig{SecretKey: secrets.NewSecureString("s")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.endpoint != reCAPTCHAVerifyURL {
		t.Errorf("got endpoint %q, want %q", v.endpoint, reCAPTCHAVerifyURL)
	}
}

func TestNewReCAPTCHAVerifier_CustomEndpointUsed(t *testing.T) {
	v, err := NewReCAPTCHAVerifier(ReCAPTCHAConfig{SecretKey: secrets.NewSecureString("s"), Endpoint: "http://test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.endpoint != "http://test" {
		t.Errorf("got endpoint %q, want %q", v.endpoint, "http://test")
	}
}

func TestNewReCAPTCHAVerifier_CustomHTTPClient(t *testing.T) {
	client := &http.Client{}
	v, err := NewReCAPTCHAVerifier(ReCAPTCHAConfig{SecretKey: secrets.NewSecureString("s"), HTTPClient: client})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.client != client {
		t.Error("custom HTTP client was not stored")
	}
}

// --------------------------------------------------------------------------
// ReCAPTCHAVerifier.Verify — v2 success path
// --------------------------------------------------------------------------

func TestReCAPTCHAVerifier_Verify_V2Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := reCAPTCHAResponse{
			Success:  true,
			Hostname: "example.com",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer srv.Close()

	v, _ := NewReCAPTCHAVerifier(ReCAPTCHAConfig{
		SecretKey:  secrets.NewSecureString("secret"),
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})

	result, err := v.Verify(context.Background(), "valid-token", "1.2.3.4", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected Success true")
	}
	if result.Hostname != "example.com" {
		t.Errorf("got hostname %q, want %q", result.Hostname, "example.com")
	}
}

// --------------------------------------------------------------------------
// ReCAPTCHAVerifier.Verify — v3 success with score
// --------------------------------------------------------------------------

func TestReCAPTCHAVerifier_Verify_V3SuccessWithScore(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := reCAPTCHAResponse{
			Success:  true,
			Score:    0.9,
			Action:   "register",
			Hostname: "example.com",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer srv.Close()

	v, _ := NewReCAPTCHAVerifier(ReCAPTCHAConfig{
		SecretKey:  secrets.NewSecureString("secret"),
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})

	result, err := v.Verify(context.Background(), "v3-token", "10.0.0.1", "site-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected Success true")
	}
	if result.Score != 0.9 {
		t.Errorf("got score %v, want 0.9", result.Score)
	}
	if result.Action != "register" {
		t.Errorf("got action %q, want %q", result.Action, "register")
	}
}

// --------------------------------------------------------------------------
// ReCAPTCHAVerifier.Verify — low score returned by upstream (v3)
// --------------------------------------------------------------------------

func TestReCAPTCHAVerifier_Verify_LowScoreReturnedByUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := reCAPTCHAResponse{
			Success:  true,
			Score:    0.1,
			Hostname: "example.com",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer srv.Close()

	v, _ := NewReCAPTCHAVerifier(ReCAPTCHAConfig{
		SecretKey:  secrets.NewSecureString("secret"),
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})

	// The verifier itself reports the score faithfully; it is the manager's
	// responsibility to enforce the threshold.
	result, err := v.Verify(context.Background(), "bot-token", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Error("expected upstream Success true even for low score")
	}
	if result.Score != 0.1 {
		t.Errorf("got score %v, want 0.1", result.Score)
	}
}

// --------------------------------------------------------------------------
// ReCAPTCHAVerifier.Verify — failure path
// --------------------------------------------------------------------------

func TestReCAPTCHAVerifier_Verify_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := reCAPTCHAResponse{
			Success:    false,
			ErrorCodes: []string{"invalid-input-response"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer srv.Close()

	v, _ := NewReCAPTCHAVerifier(ReCAPTCHAConfig{
		SecretKey:  secrets.NewSecureString("secret"),
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})

	result, err := v.Verify(context.Background(), "bad-token", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("expected Success false")
	}
	if len(result.ErrorCodes) == 0 {
		t.Fatal("expected non-empty ErrorCodes")
	}
}

// --------------------------------------------------------------------------
// ReCAPTCHAVerifier.Verify — network error
// --------------------------------------------------------------------------

func TestReCAPTCHAVerifier_Verify_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.Close()

	v, _ := NewReCAPTCHAVerifier(ReCAPTCHAConfig{
		SecretKey:  secrets.NewSecureString("secret"),
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})

	_, err := v.Verify(context.Background(), "tok", "", "")
	if err == nil {
		t.Fatal("expected network error")
	}
	var target *CaptchaNetworkError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CaptchaNetworkError, got %T", err)
	}
	if target.Provider != "recaptcha" {
		t.Errorf("got provider %q, want %q", target.Provider, "recaptcha")
	}
}

// --------------------------------------------------------------------------
// ReCAPTCHAVerifier.Verify — bad JSON response
// --------------------------------------------------------------------------

func TestReCAPTCHAVerifier_Verify_ParseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("{invalid")) //nolint:errcheck
	}))
	defer srv.Close()

	v, _ := NewReCAPTCHAVerifier(ReCAPTCHAConfig{
		SecretKey:  secrets.NewSecureString("secret"),
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})

	_, err := v.Verify(context.Background(), "tok", "", "")
	if err == nil {
		t.Fatal("expected parse error")
	}
	var target *CaptchaParseError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CaptchaParseError, got %T", err)
	}
	if target.Provider != "recaptcha" {
		t.Errorf("got provider %q, want %q", target.Provider, "recaptcha")
	}
}

// --------------------------------------------------------------------------
// ReCAPTCHAVerifier.Verify — context cancellation
// --------------------------------------------------------------------------

func TestReCAPTCHAVerifier_Verify_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {}
	}))
	defer srv.Close()

	v, _ := NewReCAPTCHAVerifier(ReCAPTCHAConfig{
		SecretKey:  secrets.NewSecureString("secret"),
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := v.Verify(ctx, "tok", "", "")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	var target *CaptchaNetworkError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CaptchaNetworkError, got %T", err)
	}
}

// --------------------------------------------------------------------------
// reCAPTCHAResponse struct
// --------------------------------------------------------------------------

func TestReCAPTCHAResponse_JSONRoundtrip(t *testing.T) {
	r := reCAPTCHAResponse{
		Success:     true,
		Score:       0.85,
		Action:      "login",
		ChallengeTS: "2024-01-01T00:00:00Z",
		Hostname:    "example.com",
		ErrorCodes:  nil,
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var out reCAPTCHAResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Score != r.Score || out.Action != r.Action {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", out, r)
	}
}
