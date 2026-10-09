package securestorage

import (
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func TestStorageCredentials_ZeroValue(t *testing.T) {
	var creds StorageCredentials
	if creds.Username != "" {
		t.Errorf("expected empty username, got %q", creds.Username)
	}
	if creds.Password.Plaintext(t.Context()) != "" {
		t.Errorf("expected empty password, got %q", creds.Password.Plaintext(t.Context()))
	}
}

func TestStorageCredentials_Fields(t *testing.T) {
	creds := StorageCredentials{
		Username: "storage-user",
		Password: secrets.MustNewSecureString(t.Context(), "storage-pass"),
	}
	defer creds.Destroy()

	if creds.Username != "storage-user" {
		t.Errorf("got %q, want %q", creds.Username, "storage-user")
	}
	if creds.Password.Plaintext(t.Context()) != "storage-pass" {
		t.Errorf("got %q, want %q", creds.Password.Plaintext(t.Context()), "storage-pass")
	}
}

// The wire form is written by the REST handler, which opens the password
// under the request's context. Generic JSON encoding has no context to open
// it with, so it must never carry the plaintext.
func TestStorageCredentials_MarshalJSONEmitsSignalCredential(t *testing.T) {
	creds := &StorageCredentials{
		Username: "acct-uuid",
		Password: secrets.MustNewSecureString(t.Context(), "hmac-derived-password"),
	}
	defer creds.Destroy()

	got, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"username":"acct-uuid","password":"hmac-derived-password"}`
	if string(got) != want {
		t.Fatalf("Marshal = %s, want %s", got, want)
	}
}

func TestStorageCredentials_Destroy(t *testing.T) {
	creds := &StorageCredentials{
		Username: "acct-uuid",
		Password: secrets.MustNewSecureString(t.Context(), "hmac-derived-password"),
	}
	creds.Destroy()
	if !creds.Password.IsDestroyed(t.Context()) {
		t.Error("Destroy must wipe the password")
	}

	// Destroy is idempotent and nil-safe.
	creds.Destroy()
	(*StorageCredentials)(nil).Destroy()
	(&StorageCredentials{Username: "acct-uuid"}).Destroy()
}
