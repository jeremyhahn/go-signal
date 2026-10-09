package directory

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// wireShape is the struct these credentials used to be marshalled through, kept
// HERE rather than in production because it is now an oracle, not an
// implementation. MarshalJSON builds the JSON by hand so the password never
// becomes a Go string; this is what proves that produces the same bytes.
type wireShape struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// The acceptance criterion for #47: the JSON a client receives must be
// identical, or this is a protocol change wearing a security fix's clothes.
//
// The corpus is chosen to hit every escaping branch — a password containing a
// quote, a backslash, an angle bracket or a control byte is exactly where a
// hand-built encoder and encoding/json would diverge, and exactly the input
// nobody tries by hand.
func TestDirectoryCredentials_MarshalJSON_ByteIdenticalToTheOldStructPath(t *testing.T) {
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
			c := &DirectoryCredentials{Username: "acct-uuid", Password: secrets.MustNewSecureString(pw)}
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
func TestDirectoryCredentials_UnmarshalJSON_RoundTripsEveryEscape(t *testing.T) {
	for _, pw := range []string{
		"hunter2", `quote"inside`, `back\\slash`, "angle<brackets>&", "\t\n\r", "\x01\x1f", "é☃𝄞", "  ",
	} {
		t.Run(pw, func(t *testing.T) {
			encoded, err := json.Marshal(wireShape{Username: "u", Password: pw})
			if err != nil {
				t.Fatalf("oracle marshal: %v", err)
			}
			var c DirectoryCredentials
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
