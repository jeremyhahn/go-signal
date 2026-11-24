package securevaluerecovery

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// svrWireShape is the reference struct: AppendJSON must produce the same bytes.
type svrWireShape struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// The JSON must be byte-identical; the corpus hits every escaping branch.
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

// AppendJSON must append to, not overwrite, the caller's buffer.
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
