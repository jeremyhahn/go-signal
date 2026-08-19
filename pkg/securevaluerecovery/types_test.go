package securevaluerecovery

import (
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func TestSVRCredentials_ZeroValue(t *testing.T) {
	var creds SVRCredentials
	if creds.Username != "" {
		t.Errorf("expected empty username, got %q", creds.Username)
	}
	if creds.Password.Plaintext() != "" {
		t.Errorf("expected empty password, got %q", creds.Password.Plaintext())
	}
}

func TestSVRCredentials_Fields(t *testing.T) {
	creds := SVRCredentials{
		Username: "svr-user",
		Password: secrets.MustNewSecureString("svr-pass"),
	}
	if creds.Username != "svr-user" {
		t.Errorf("got %q, want %q", creds.Username, "svr-user")
	}
	if creds.Password.Plaintext() != "svr-pass" {
		t.Errorf("got %q, want %q", creds.Password.Plaintext(), "svr-pass")
	}
}

func TestAuthCheckRequest_ZeroValue(t *testing.T) {
	var req AuthCheckRequest
	if req.Passwords != nil {
		t.Errorf("expected nil passwords, got %v", req.Passwords)
	}
}

func TestAuthCheckRequest_Fields(t *testing.T) {
	req := AuthCheckRequest{Passwords: []string{"a", "b", "c"}}
	if len(req.Passwords) != 3 {
		t.Errorf("got %d passwords, want 3", len(req.Passwords))
	}
}

func TestAuthCheckResponse_ZeroValue(t *testing.T) {
	var resp AuthCheckResponse
	if resp.Matches != nil {
		t.Errorf("expected nil matches, got %v", resp.Matches)
	}
}

func TestAuthCheckResponse_Fields(t *testing.T) {
	resp := AuthCheckResponse{
		Matches: map[string]string{"pw1": "match", "pw2": "no-match"},
	}
	if len(resp.Matches) != 2 {
		t.Errorf("got %d matches, want 2", len(resp.Matches))
	}
	if resp.Matches["pw1"] != "match" {
		t.Errorf("got %q, want %q", resp.Matches["pw1"], "match")
	}
}
