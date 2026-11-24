package securestorage

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// wireShape is the reference struct: MarshalJSON must produce the same bytes.
type wireShape struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// The JSON must be byte-identical; the corpus hits every escaping branch.
func TestStorageCredentials_MarshalJSON_ByteIdenticalToTheOldStructPath(t *testing.T) {
	passwords := []string{
		"hunter2",
		"1724371200:9f8e7d6c5b4a",
		"user:1724371200:deadbeef",
		`quote"inside`,
		`back\\slash`,
		"angle<brackets>and&amp",
		"tab\there\nnewline\rreturn",
		"\x00\x01\x1f control",
		"é☃𝄞 unicode",
		"   line terminators",
		"  leading and trailing  ",
	}
	for _, pw := range passwords {
		t.Run(pw, func(t *testing.T) {
			c := &StorageCredentials{Username: "acct-uuid", Password: secrets.MustNewSecureString(pw)}
			defer c.Destroy()

			// Through AppendJSON, which is what writeJSON actually calls in
			// production, AND through the Marshaler that delegates to it.
			// Testing only json.Marshal would stop pinning the production
			// mechanism the moment the two are decoupled.
			got, err := c.AppendJSON(nil)
			if err != nil {
				t.Fatalf("AppendJSON: %v", err)
			}
			viaMarshal, err := json.Marshal(c)
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			want, err := json.Marshal(wireShape{Username: "acct-uuid", Password: pw})
			if err != nil {
				t.Fatalf("oracle marshal: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("wire form changed:\n  got  %s\n  want %s", got, want)
			}
			if !bytes.Equal(viaMarshal, want) {
				t.Errorf("MarshalJSON diverges from AppendJSON:\n  got  %s\n  want %s", viaMarshal, want)
			}
		})
	}
}

// And the reverse direction: anything the old shape could produce must decode
// back to the same password, through the byte path.
func TestStorageCredentials_UnmarshalJSON_RoundTripsEveryEscape(t *testing.T) {
	for _, pw := range []string{
		"hunter2", `quote"inside`, `back\\slash`, "angle<brackets>&", "\t\n\r", "\x01\x1f", "é☃𝄞", "  ",
	} {
		t.Run(pw, func(t *testing.T) {
			encoded, err := json.Marshal(wireShape{Username: "u", Password: pw})
			if err != nil {
				t.Fatalf("oracle marshal: %v", err)
			}
			var c StorageCredentials
			if err := json.Unmarshal(encoded, &c); err != nil {
				t.Fatalf("UnmarshalJSON: %v", err)
			}
			defer c.Destroy()

			if c.Username != "u" {
				t.Errorf("username = %q, want %q", c.Username, "u")
			}
			if !c.Password.Equals(pw) {
				t.Errorf("password did not round trip for %q", pw)
			}
		})
	}
}
