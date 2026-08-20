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
	if creds.Password.Plaintext() != "" {
		t.Errorf("expected empty password, got %q", creds.Password.Plaintext())
	}
}

func TestStorageCredentials_Fields(t *testing.T) {
	creds := StorageCredentials{
		Username: "storage-user",
		Password: secrets.MustNewSecureString("storage-pass"),
	}
	defer creds.Destroy()

	if creds.Username != "storage-user" {
		t.Errorf("got %q, want %q", creds.Username, "storage-user")
	}
	if creds.Password.Plaintext() != "storage-pass" {
		t.Errorf("got %q, want %q", creds.Password.Plaintext(), "storage-pass")
	}
}

// TestStorageCredentials_WireFormUnchanged is the compatibility pin for moving
// Password into protected memory. storage-service clients parse this response,
// so the emitted JSON must stay byte-identical to what the plain-string struct
// produced — the change is where the credential lives in memory, not what goes
// on the wire.
func TestStorageCredentials_WireFormUnchanged(t *testing.T) {
	creds := StorageCredentials{
		Username: "acct-uuid",
		Password: secrets.MustNewSecureString("hmac-derived-password"),
	}
	defer creds.Destroy()

	got, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Exactly what `struct{Username, Password string}` with these json tags
	// emitted before this change, field order included.
	const want = `{"username":"acct-uuid","password":"hmac-derived-password"}`
	if string(got) != want {
		t.Errorf("wire form changed:\n got %s\nwant %s", got, want)
	}
}

// TestStorageCredentials_MarshalFailsClosedOnWipedPassword is the reason the
// type carries an explicit marshaller instead of leaning on SecureString's
// default.
//
// A credential whose password has been wiped must FAIL the response, not
// serialise as an empty string: the client treats whatever arrives in that
// field as its bearer token, so an empty password is a credential it would
// present and be rejected for. writeJSON turns this error into a 500, which
// is the fail-closed outcome end to end.
//
// Reverting MarshalJSON to Plaintext (which returns "" instead of erroring)
// makes this fail.
func TestStorageCredentials_MarshalFailsClosedOnWipedPassword(t *testing.T) {
	creds := StorageCredentials{
		Username: "acct-uuid",
		Password: secrets.MustNewSecureString("hmac-derived-password"),
	}
	creds.Password.Destroy()

	got, err := json.Marshal(creds)
	if err == nil {
		t.Fatalf("Marshal succeeded on a wiped password, emitting %s", got)
	}
}

// TestStorageCredentials_UnmarshalLandsInProtectedMemory pins the return trip:
// a credential parsed from the wire must not sit in a heap string.
func TestStorageCredentials_UnmarshalLandsInProtectedMemory(t *testing.T) {
	var creds StorageCredentials
	if err := json.Unmarshal([]byte(`{"username":"u","password":"p"}`), &creds); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	defer creds.Destroy()

	if creds.Username != "u" {
		t.Errorf("username = %q, want %q", creds.Username, "u")
	}
	if creds.Password.IsDestroyed() {
		t.Fatal("password did not land in protected memory")
	}
	if got := creds.Password.Plaintext(); got != "p" {
		t.Errorf("password = %q, want %q", got, "p")
	}
}

// TestStorageCredentials_UnmarshalRejectsAnEmptyPassword covers the fail-closed
// half of the return trip: an issued bearer credential is never legitimately
// empty, so a response carrying one is malformed and must fail here rather
// than propagate as a credential that only fails at some later use.
func TestStorageCredentials_UnmarshalRejectsAnEmptyPassword(t *testing.T) {
	var creds StorageCredentials
	if err := json.Unmarshal([]byte(`{"username":"u","password":""}`), &creds); err == nil {
		t.Fatal("Unmarshal accepted an empty password")
	}
}
