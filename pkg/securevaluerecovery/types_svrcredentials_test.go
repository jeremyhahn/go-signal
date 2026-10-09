package securevaluerecovery

import (
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// The wire form is written by the REST handlers, which open the password
// under the request's context. Generic JSON encoding has no context to open
// it with, so it must never carry the plaintext.
func TestSVRCredentials_MarshalJSONEmitsSignalCredential(t *testing.T) {
	creds := &SVRCredentials{
		Username: "svr-user",
		Password: secrets.MustNewSecureString(t.Context(), "svr-pass"),
	}
	defer creds.Destroy()

	got, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"username":"svr-user","password":"svr-pass"}`
	if string(got) != want {
		t.Fatalf("Marshal = %s, want %s", got, want)
	}
}

func TestSVRCredentials_Destroy(t *testing.T) {
	creds := &SVRCredentials{
		Username: "svr-user",
		Password: secrets.MustNewSecureString(t.Context(), "svr-pass"),
	}
	creds.Destroy()
	if !creds.Password.IsDestroyed(t.Context()) {
		t.Error("Destroy must wipe the password")
	}
	if got := creds.Password.Plaintext(t.Context()); got != "" {
		t.Errorf("Plaintext after Destroy = %q, want empty", got)
	}

	// Destroy is idempotent and nil-safe.
	creds.Destroy()
	(*SVRCredentials)(nil).Destroy()
	(&SVRCredentials{Username: "svr-user"}).Destroy()
}
