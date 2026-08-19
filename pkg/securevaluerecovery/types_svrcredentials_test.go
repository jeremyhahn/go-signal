package securevaluerecovery

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// The SVR client is the intended bearer of this credential, so the wire form
// must carry the plaintext password under the same field names Java's
// /v2/backup/auth and /v2/svr/auth emit.
func TestSVRCredentials_MarshalJSON_WireShape(t *testing.T) {
	creds := &SVRCredentials{
		Username: "svr-user",
		Password: secrets.MustNewSecureString("svr-pass"),
	}
	got, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"username":"svr-user","password":"svr-pass"}`
	if string(got) != want {
		t.Errorf("wire form = %s, want %s", got, want)
	}
}

// A destroyed or absent password fails the response rather than serialising
// an empty password the client would treat as a usable SVR credential.
func TestSVRCredentials_MarshalJSON_DestroyedPassword(t *testing.T) {
	creds := &SVRCredentials{
		Username: "svr-user",
		Password: secrets.MustNewSecureString("svr-pass"),
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

	creds.Destroy()
	(*SVRCredentials)(nil).Destroy()
}

// The same holds for a credential that never carried a password.
func TestSVRCredentials_MarshalJSON_UnsetPassword(t *testing.T) {
	creds := &SVRCredentials{Username: "svr-user"}
	if _, err := json.Marshal(creds); err == nil {
		t.Fatal("expected marshalling an unset credential to fail")
	}
}

func TestSVRCredentials_UnmarshalJSON_RoundTrip(t *testing.T) {
	var creds SVRCredentials
	if err := json.Unmarshal([]byte(`{"username":"u","password":"p"}`), &creds); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if creds.Username != "u" {
		t.Errorf("Username = %q, want u", creds.Username)
	}
	if creds.Password.Plaintext() != "p" {
		t.Errorf("Password = %q, want p", creds.Password.Plaintext())
	}
}

func TestSVRCredentials_UnmarshalJSON_Malformed(t *testing.T) {
	var creds SVRCredentials
	if err := json.Unmarshal([]byte(`{"password":7}`), &creds); err == nil {
		t.Error("expected error for malformed body")
	}
}

// Decoding into an SVRCredentials that already holds a password must wipe the
// previous protected allocation instead of abandoning it.
func TestSVRCredentials_UnmarshalJSON_DestroysReplacedPassword(t *testing.T) {
	var creds SVRCredentials
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

// An SVR credential without a password is malformed: decoding must fail
// rather than yield a credential that only breaks at some later use.
func TestSVRCredentials_UnmarshalJSON_EmptyPassword(t *testing.T) {
	for name, body := range map[string]string{
		"explicitly empty": `{"username":"u","password":""}`,
		"omitted":          `{"username":"u"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var creds SVRCredentials
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
func TestSVRCredentials_UnmarshalJSON_FailedDecodeKeepsExistingPassword(t *testing.T) {
	creds := &SVRCredentials{
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

// The REST handlers marshal the credential and then wipe it. This pins that
// order: the wire body carries the plaintext, and the protected copy is
// unusable afterwards.
func TestSVRCredentials_MarshalThenDestroy(t *testing.T) {
	password, err := secrets.NewSecureString("svr-password")
	if err != nil {
		t.Fatalf("NewSecureString: %v", err)
	}
	creds := &SVRCredentials{Username: "u", Password: password}

	body, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(body) != `{"username":"u","password":"svr-password"}` {
		t.Errorf("wire body = %s", body)
	}

	creds.Destroy()
	if !creds.Password.IsDestroyed() {
		t.Error("password must be wiped after Destroy")
	}
	if got := creds.Password.Plaintext(); got != "" {
		t.Errorf("Plaintext after Destroy = %q, want empty", got)
	}
}
