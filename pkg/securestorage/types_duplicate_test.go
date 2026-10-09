package securestorage

import (
	"encoding/json"
	"errors"
	"testing"
)

// Before the password was decoded to bytes it was a string field, and
// encoding/json rejected a wrong-typed occurrence of it even when a later
// duplicate was a valid string. That rejection must survive the change.
func TestStorageCredentials_UnmarshalJSON_RejectsWrongTypedDuplicatePassword(t *testing.T) {
	for _, body := range []string{
		`{"username":"u","password":123,"password":"ok"}`,
		`{"username":"u","password":"ok","password":123}`,
		`{"username":"u","password":true,"password":"ok"}`,
		`{"username":"u","password":{},"password":"ok"}`,
		`{"username":"u","password":["x"],"password":"ok"}`,
		`{"username":"u","password":null,"password":7}`,
	} {
		t.Run(body, func(t *testing.T) {
			var creds StorageCredentials
			err := json.Unmarshal([]byte(body), &creds)
			var typeErr *json.UnmarshalTypeError
			if !errors.As(err, &typeErr) {
				t.Fatalf("error = %v, want *json.UnmarshalTypeError", err)
			}
			if creds.Password != nil {
				t.Error("a rejected decode must not leave a password behind")
			}
		})
	}
}

// Duplicates that a string field accepted still decode, to the same value.
func TestStorageCredentials_UnmarshalJSON_ValidDuplicatePasswordDecodes(t *testing.T) {
	for body, want := range map[string]string{
		`{"username":"u","password":"first","password":"second"}`: "second",
		`{"username":"u","password":"kept","password":null}`:      "kept",
		`{"username":"u","password":null,"password":"late"}`:      "late",
	} {
		t.Run(body, func(t *testing.T) {
			var creds StorageCredentials
			defer creds.Destroy()
			if err := json.Unmarshal([]byte(body), &creds); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got := creds.Password.Plaintext(); got != want {
				t.Errorf("password = %q, want %q", got, want)
			}
		})
	}
}
