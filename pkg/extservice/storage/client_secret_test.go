package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func TestNewHTTP_RejectsUnsetAndDestroyedSharedSecrets(t *testing.T) {
	destroyed := secrets.MustNewSecureString(t.Context(), "k")
	destroyed.Destroy()

	for name, secret := range map[string]*secrets.SecureString{
		"nil":       nil,
		"unset":     secrets.MustNewSecureString(t.Context(), ""),
		"destroyed": destroyed,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewHTTP(t.Context(), HTTPConfig{BaseURL: "https://example", SharedSecret: secret}); err == nil {
				t.Error("expected NewHTTP to reject the shared secret")
			}
		})
	}
}

// TestNewHTTP_ClonesTheSharedSecret covers the ownership contract: Close must
// not reach back into the caller's secret, which the process config wipes
// separately.
func TestNewHTTP_ClonesTheSharedSecret(t *testing.T) {
	src := secrets.MustNewSecureString(t.Context(), "shared-secret")
	defer src.Destroy()

	c, err := NewHTTP(t.Context(), HTTPConfig{BaseURL: "https://example", SharedSecret: src})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if src.IsDestroyed(t.Context()) {
		t.Error("Close wiped the caller's secret")
	}
	if got := src.Plaintext(t.Context()); got != "shared-secret" {
		t.Errorf("caller's secret = %q, want %q", got, "shared-secret")
	}
}

func TestClose_WipesTheSecretAndSubsequentCallsFailClosed(t *testing.T) {
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c, err := NewHTTP(t.Context(), HTTPConfig{BaseURL: srv.URL, SharedSecret: secrets.MustNewSecureString(t.Context(), "shared-secret")})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := c.DeleteStoredData(context.Background(), "acct"); err == nil {
		t.Error("expected an error once the shared secret is wiped")
	}
	if reached {
		t.Error("an unauthenticated request reached the server after Close")
	}
}

func TestClose_IsIdempotent(t *testing.T) {
	c, err := NewHTTP(t.Context(), HTTPConfig{BaseURL: "https://example", SharedSecret: secrets.MustNewSecureString(t.Context(), "s")})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
