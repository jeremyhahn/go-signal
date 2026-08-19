package directory

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func TestDirectoryCredentials_ZeroValue(t *testing.T) {
	var creds DirectoryCredentials
	if creds.Username != "" {
		t.Errorf("expected empty username, got %q", creds.Username)
	}
	if creds.Password.Plaintext() != "" {
		t.Errorf("expected empty password, got %q", creds.Password.Plaintext())
	}
}

func TestDirectoryCredentials_Fields(t *testing.T) {
	creds := DirectoryCredentials{
		Username: "alice",
		Password: secrets.MustNewSecureString("secret-pw"),
	}
	if creds.Username != "alice" {
		t.Errorf("got %q, want %q", creds.Username, "alice")
	}
	if creds.Password.Plaintext() != "secret-pw" {
		t.Errorf("got %q, want %q", creds.Password.Plaintext(), "secret-pw")
	}
}

// The CDS client is the intended bearer of this credential, so the wire form
// must carry the plaintext password under the same field names Java's
// /v2/directory/auth emits. A regression here silently hands clients an
// unusable credential.
func TestDirectoryCredentials_MarshalJSON_WireShape(t *testing.T) {
	creds := &DirectoryCredentials{
		Username: "alice",
		Password: secrets.MustNewSecureString("secret-pw"),
	}
	got, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"username":"alice","password":"secret-pw"}`
	if string(got) != want {
		t.Errorf("wire form = %s, want %s", got, want)
	}
}

// A destroyed or absent password fails the response: serialising it as an
// empty string would hand the client a credential CDS will reject, with a 200
// telling it the credential is good.
func TestDirectoryCredentials_MarshalJSON_DestroyedPassword(t *testing.T) {
	creds := &DirectoryCredentials{
		Username: "alice",
		Password: secrets.MustNewSecureString("secret-pw"),
	}
	creds.Destroy()

	got, err := json.Marshal(creds)
	if err == nil {
		t.Fatalf("expected marshalling a destroyed credential to fail, got %s", got)
	}
	var unavailable *secrets.UnavailableSecretError
	if !errors.As(err, &unavailable) {
		t.Errorf("error = %v, want *secrets.UnavailableSecretError", err)
	}

	// Destroy is idempotent.
	creds.Destroy()
	(*DirectoryCredentials)(nil).Destroy()
}

// The same holds for a credential that never carried a password.
func TestDirectoryCredentials_MarshalJSON_UnsetPassword(t *testing.T) {
	creds := &DirectoryCredentials{Username: "alice"}
	if _, err := json.Marshal(creds); err == nil {
		t.Fatal("expected marshalling an unset credential to fail")
	}
}

func TestDirectoryCredentials_UnmarshalJSON_RoundTrip(t *testing.T) {
	var creds DirectoryCredentials
	if err := json.Unmarshal([]byte(`{"username":"bob","password":"pw"}`), &creds); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if creds.Username != "bob" {
		t.Errorf("Username = %q, want bob", creds.Username)
	}
	if creds.Password.Plaintext() != "pw" {
		t.Errorf("Password = %q, want pw", creds.Password.Plaintext())
	}
}

func TestDirectoryCredentials_UnmarshalJSON_Malformed(t *testing.T) {
	var creds DirectoryCredentials
	if err := json.Unmarshal([]byte(`{"username":42}`), &creds); err == nil {
		t.Error("expected error for malformed body")
	}
}

// Decoding into a DirectoryCredentials that already holds a password must
// wipe the previous protected allocation instead of abandoning it.
func TestDirectoryCredentials_UnmarshalJSON_DestroysReplacedPassword(t *testing.T) {
	var creds DirectoryCredentials
	if err := json.Unmarshal([]byte(`{"username":"u1","password":"p1"}`), &creds); err != nil {
		t.Fatalf("first unmarshal: %v", err)
	}
	first := creds.Password
	if first == nil || first.IsDestroyed() {
		t.Fatal("expected a live password after the first decode")
	}

	if err := json.Unmarshal([]byte(`{"username":"u2","password":"p2"}`), &creds); err != nil {
		t.Fatalf("second unmarshal: %v", err)
	}
	if got := creds.Password.Plaintext(); got != "p2" {
		t.Errorf("password = %q, want %q", got, "p2")
	}
	if !first.IsDestroyed() {
		t.Error("the replaced password must be wiped, not abandoned")
	}
}

// A CDS credential without a password is malformed: decoding must fail
// rather than yield a credential that only breaks at some later use.
func TestDirectoryCredentials_UnmarshalJSON_EmptyPassword(t *testing.T) {
	for name, body := range map[string]string{
		"explicitly empty": `{"username":"u","password":""}`,
		"omitted":          `{"username":"u"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var creds DirectoryCredentials
			err := json.Unmarshal([]byte(body), &creds)
			if err == nil {
				t.Fatal("expected decoding a passwordless credential to fail")
			}
			var empty *secrets.EmptySecretError
			if !errors.As(err, &empty) {
				t.Errorf("error = %v, want *secrets.EmptySecretError", err)
			}
			if creds.Password != nil {
				t.Error("a failed decode must not leave a password behind")
			}
		})
	}
}

// A failed decode must not wipe the password the value already held.
func TestDirectoryCredentials_UnmarshalJSON_FailedDecodeKeepsExistingPassword(t *testing.T) {
	creds := &DirectoryCredentials{
		Username: "u1",
		Password: secrets.MustNewSecureString("p1"),
	}
	if err := json.Unmarshal([]byte(`{"username":"u2","password":""}`), creds); err == nil {
		t.Fatal("expected the decode to fail")
	}
	if got := creds.Password.Plaintext(); got != "p1" {
		t.Errorf("password = %q, want the original %q", got, "p1")
	}
}
