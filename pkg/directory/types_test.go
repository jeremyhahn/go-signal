package directory

import (
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func TestDirectoryCredentials_ZeroValue(t *testing.T) {
	var creds DirectoryCredentials
	if creds.Username != "" {
		t.Errorf("expected empty username, got %q", creds.Username)
	}
	if creds.Password.Plaintext(t.Context()) != "" {
		t.Errorf("expected empty password, got %q", creds.Password.Plaintext(t.Context()))
	}
}

func TestDirectoryCredentials_Fields(t *testing.T) {
	creds := DirectoryCredentials{
		Username: "alice",
		Password: secrets.MustNewSecureString(t.Context(), "secret-pw"),
	}
	if creds.Username != "alice" {
		t.Errorf("got %q, want %q", creds.Username, "alice")
	}
	if creds.Password.Plaintext(t.Context()) != "secret-pw" {
		t.Errorf("got %q, want %q", creds.Password.Plaintext(t.Context()), "secret-pw")
	}
}

// The wire form is written by the REST handler, which opens the password
// under the request's context. Generic JSON encoding has no context to open
// it with, so it must never carry the plaintext.
func TestDirectoryCredentials_MarshalJSONEmitsSignalCredential(t *testing.T) {
	creds := &DirectoryCredentials{
		Username: "alice",
		Password: secrets.MustNewSecureString(t.Context(), "secret-pw"),
	}
	defer creds.Destroy()

	got, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"username":"alice","password":"secret-pw"}`
	if string(got) != want {
		t.Fatalf("Marshal = %s, want %s", got, want)
	}
}

func TestDirectoryCredentials_Destroy(t *testing.T) {
	creds := &DirectoryCredentials{
		Username: "alice",
		Password: secrets.MustNewSecureString(t.Context(), "secret-pw"),
	}
	creds.Destroy()
	if !creds.Password.IsDestroyed(t.Context()) {
		t.Error("Destroy must wipe the password")
	}

	// Destroy is idempotent and nil-safe.
	creds.Destroy()
	(*DirectoryCredentials)(nil).Destroy()
	(&DirectoryCredentials{Username: "alice"}).Destroy()
}
