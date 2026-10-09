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
// NewHCaptchaVerifier construction
// --------------------------------------------------------------------------

func TestNewHCaptchaVerifier_Success(t *testing.T) {
	v, err := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{SecretKey: secrets.MustNewSecureString(t.Context(), "secret")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil verifier")
	}
}

func TestNewHCaptchaVerifier_EmptySecretKey(t *testing.T) {
	_, err := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{})
	if err == nil {
		t.Fatal("expected error for empty secret key")
	}
	var target *HCaptchaConfigError
	if !errors.As(err, &target) {
		t.Fatalf("expected *HCaptchaConfigError, got %T", err)
	}
}

func TestNewHCaptchaVerifier_UsesDefaultEndpoint(t *testing.T) {
	v, err := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{SecretKey: secrets.MustNewSecureString(t.Context(), "s")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.endpoint != hCaptchaVerifyURL {
		t.Errorf("got endpoint %q, want %q", v.endpoint, hCaptchaVerifyURL)
	}
}

func TestNewHCaptchaVerifier_CustomEndpointUsed(t *testing.T) {
	v, err := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{SecretKey: secrets.MustNewSecureString(t.Context(), "s"), Endpoint: "http://test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.endpoint != "http://test" {
		t.Errorf("got endpoint %q, want %q", v.endpoint, "http://test")
	}
}

func TestNewHCaptchaVerifier_CustomHTTPClient(t *testing.T) {
	client := &http.Client{}
	v, err := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{SecretKey: secrets.MustNewSecureString(t.Context(), "s"), HTTPClient: client})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.client != client {
		t.Error("custom HTTP client was not stored")
	}
}

// --------------------------------------------------------------------------
// HCaptchaVerifier.Verify — success path
// --------------------------------------------------------------------------

func TestHCaptchaVerifier_Verify_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := hCaptchaResponse{
			Success:  true,
			Hostname: "example.com",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer srv.Close()

	v, _ := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{
		SecretKey:  secrets.MustNewSecureString(t.Context(), "secret"),
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
// HCaptchaVerifier.Verify — failure path
// --------------------------------------------------------------------------

func TestHCaptchaVerifier_Verify_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := hCaptchaResponse{
			Success:    false,
			ErrorCodes: []string{"invalid-input-response"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
	}))
	defer srv.Close()

	v, _ := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{
		SecretKey:  secrets.MustNewSecureString(t.Context(), "secret"),
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
	if result.ErrorCodes[0] != "invalid-input-response" {
		t.Errorf("got error code %q, want %q", result.ErrorCodes[0], "invalid-input-response")
	}
}

// --------------------------------------------------------------------------
// HCaptchaVerifier.Verify — network error
// --------------------------------------------------------------------------

func TestHCaptchaVerifier_Verify_NetworkError(t *testing.T) {
	// Use a closed server so all connections are refused immediately.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.Close()

	v, _ := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{
		SecretKey:  secrets.MustNewSecureString(t.Context(), "secret"),
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
	if target.Provider != "hcaptcha" {
		t.Errorf("got provider %q, want %q", target.Provider, "hcaptcha")
	}
}

// --------------------------------------------------------------------------
// HCaptchaVerifier.Verify — bad JSON response
// --------------------------------------------------------------------------

func TestHCaptchaVerifier_Verify_ParseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not-json")) //nolint:errcheck
	}))
	defer srv.Close()

	v, _ := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{
		SecretKey:  secrets.MustNewSecureString(t.Context(), "secret"),
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
	if target.Provider != "hcaptcha" {
		t.Errorf("got provider %q, want %q", target.Provider, "hcaptcha")
	}
}

// --------------------------------------------------------------------------
// HCaptchaVerifier.Verify — context cancellation
// --------------------------------------------------------------------------

func TestHCaptchaVerifier_Verify_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Deliberately never writes a response so the context times out.
		select {}
	}))
	defer srv.Close()

	v, _ := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{
		SecretKey:  secrets.MustNewSecureString(t.Context(), "secret"),
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

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
// HCaptchaVerifier.Verify — remoteIP is omitted when blank
// --------------------------------------------------------------------------

func TestHCaptchaVerifier_Verify_OmitsBlankRemoteIP(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm() //nolint:errcheck
		gotBody = r.FormValue("remoteip")
		json.NewEncoder(w).Encode(hCaptchaResponse{Success: true}) //nolint:errcheck
	}))
	defer srv.Close()

	v, _ := NewHCaptchaVerifier(t.Context(), HCaptchaConfig{
		SecretKey:  secrets.MustNewSecureString(t.Context(), "secret"),
		Endpoint:   srv.URL,
		HTTPClient: srv.Client(),
	})

	v.Verify(context.Background(), "tok", "", "") //nolint:errcheck

	if gotBody != "" {
		t.Errorf("expected empty remoteip, got %q", gotBody)
	}
}

// --------------------------------------------------------------------------
// hCaptchaResponse struct
// --------------------------------------------------------------------------

func TestHCaptchaResponse_JSONRoundtrip(t *testing.T) {
	r := hCaptchaResponse{
		Success:     true,
		ChallengeTS: "2024-01-01T00:00:00Z",
		Hostname:    "test.com",
		ErrorCodes:  nil,
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var out hCaptchaResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Success != r.Success || out.Hostname != r.Hostname {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", out, r)
	}
}
