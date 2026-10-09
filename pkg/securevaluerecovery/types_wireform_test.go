package securevaluerecovery

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// svrWireShape is the struct this credential used to be marshalled through,
// kept HERE rather than in production because it is now an oracle, not an
// implementation. AppendJSON builds the JSON by hand so the password never
// becomes a Go string; this is what proves that produces the same bytes.
type svrWireShape struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// The acceptance criterion for #47: the JSON a client receives must be
// identical, or this is a protocol change wearing a security fix's clothes.
//
// The corpus hits every escaping branch — a password containing a quote, a
// backslash, an angle bracket or a control byte is exactly where a hand-built
// encoder and encoding/json would diverge, and exactly the input nobody tries
// by hand.
func TestSVRCredentials_AppendJSON_ByteIdenticalToTheOldStructPath(t *testing.T) {
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
		"  leading and trailing  ",
	}
	for _, pw := range passwords {
		t.Run(pw, func(t *testing.T) {
			c := &SVRCredentials{Username: "acct-uuid", Password: secrets.MustNewSecureString(pw)}
			defer c.Destroy()

			// Through the production path (AppendJSON), and through the
			// Marshaler that delegates to it — both must match the oracle.
			got, err := c.AppendJSON(nil)
			if err != nil {
				t.Fatalf("AppendJSON: %v", err)
			}
			viaMarshal, err := json.Marshal(c)
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			want, err := json.Marshal(svrWireShape{Username: "acct-uuid", Password: pw})
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

// AppendJSON must APPEND, not overwrite: it writes into a buffer the caller
// owns and may already have written into.
func TestSVRCredentials_AppendJSON_AppendsToExistingBuffer(t *testing.T) {
	c := &SVRCredentials{Username: "u", Password: secrets.MustNewSecureString("pw")}
	defer c.Destroy()

	got, err := c.AppendJSON([]byte("PREFIX"))
	if err != nil {
		t.Fatalf("AppendJSON: %v", err)
	}
	if !bytes.HasPrefix(got, []byte("PREFIX{")) {
		t.Errorf("AppendJSON did not append to the caller's buffer: %s", got)
	}
}

// An unavailable credential must fail the response rather than emit an empty
// password the client would treat as usable.
func TestSVRCredentials_AppendJSON_DestroyedPasswordFailsClosed(t *testing.T) {
	c := &SVRCredentials{Username: "u", Password: secrets.MustNewSecureString("pw")}
	c.Destroy()
	if _, err := c.AppendJSON(nil); err == nil {
		t.Error("destroyed password serialised without error; a client would receive an empty credential")
	}
}
