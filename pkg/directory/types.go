package directory

import (
	"context"
	"encoding/json"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// DirectoryCredentials contains authentication credentials for the contact
// discovery service.
//
// Password is the CDS bearer credential and is held in protected memory
// between issuance and the response that hands it to its bearer. The type has
// no JSON form of its own: opening the secret takes a context, which a
// marshaller has no way to receive, so the REST layer reveals it under the
// request's context and writes the wire shape itself. Marshalled directly,
// Password falls back to SecureString's redacting marshaller.
type DirectoryCredentials struct {
	Username string
	Password *secrets.SecureString
}

// Compile-time proof that this credential serialises through the owned-buffer
// path. Without it, writeJSON silently falls back to json.Marshal, which
// abandons an unwiped copy of the password — a regression that no test can
// observe, because the wire bytes are identical either way. Breaking the build
// is the only reliable guard.
var _ secrets.JSONAppender = DirectoryCredentials{}

// AppendJSON implements secrets.JSONAppender, emitting the credential in the
// Signal-compatible `{"username":…,"password":…}` shape into a buffer the
// CALLER owns and wipes.
//
// This, not MarshalJSON, is the production path: writeJSON prefers it so the
// plaintext lands in exactly one buffer with exactly one owner. See the
// JSONAppender doc for why a json.Marshaler cannot be made safe here.
func (c DirectoryCredentials) AppendJSON(ctx context.Context, dst []byte) ([]byte, error) {
	// The password is written straight from protected memory into the output
	// buffer and never becomes a Go string. The previous spelling —
	// Reveal() into a string, then json.Marshal a struct — put the plaintext
	// in memory that cannot be wiped, twice: once in the revealed string and
	// again in encoding/json's buffer.
	//
	// The username is not secret, so encoding/json handles it, and the field
	// order matches the struct that used to be marshalled. That is what keeps
	// the wire form byte-identical, which the tests assert rather than assume.
	user, err := json.Marshal(c.Username)
	if err != nil {
		return dst, err
	}
	// Grow once for the whole fixed part. A reallocation partway would abandon
	// an array that, once the password is appended below, holds plaintext
	// nothing can reach to wipe.
	dst = secrets.Grow(dst, len(`{"username":`)+len(user)+len(`,"password":`))
	dst = append(dst, `{"username":`...)
	dst = append(dst, user...)
	dst = append(dst, `,"password":`...)

	// Reveal semantics are preserved: a password that is unset or already
	// wiped fails the response rather than handing the client an empty
	// credential it would treat as valid. writeJSON turns this into a 500.
	//
	// dst is returned even on failure rather than wiped here: it belongs to
	// the caller, may already hold unrelated bytes, and a partial body still
	// needs wiping — which the caller does on every path.
	dst, err = c.Password.AppendJSONString(ctx, dst)
	if err != nil {
		return dst, err
	}
	// Grow before the closing brace: a bare append here could reallocate and
	// abandon the array holding the password, which nothing could then wipe.
	dst = secrets.Grow(dst, 1)
	return append(dst, '}'), nil
}

// MarshalJSON implements encoding/json.Marshaler, emitting the credential in
// the Signal-compatible `{"username":…,"password":…}` shape.
//
// WARNING: the returned buffer holds the plaintext contact-discovery password, and
// encoding/json copies it into its own buffer and drops this one — leaving an
// unwiped heap allocation that no later wipe can reach. That is a property of
// the Marshaler contract, not of this implementation. Production responses do
// not take this path; writeJSON uses AppendJSON.
//
// It is kept because removing it is worse: with no Marshaler, a value nested
// in some other struct would marshal through SecureString's default, which
// redacts, and the credential would silently become "[REDACTED]" on the wire
// instead of failing loudly. Wire correctness with one unwiped buffer beats a
// silent protocol break.
func (c DirectoryCredentials) MarshalJSON() ([]byte, error) {
	return c.AppendJSON(context.Background(), nil)
}

// UnmarshalJSON implements encoding/json.Unmarshaler so a credential that
// crossed the wire lands back in protected memory rather than a heap string.
func (c *DirectoryCredentials) UnmarshalJSON(data []byte) error {
	// secrets.JSONStringBytes, not string: unmarshalling the password into a
	// string field would land the credential in unwipeable memory before it is
	// ever sealed. It validates every occurrence of a duplicated key, so a
	// wrong-typed password fails exactly as the string field did.
	var raw struct {
		Username string                  `json:"username"`
		Password secrets.JSONStringBytes `json:"password"`
	}
	// Registered before the decode so that a failed Unmarshal, which can still
	// have populated the field, is covered too.
	defer raw.Password.Wipe()
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// An absent, null or empty password reaches the sealer as empty bytes and
	// fails there, which is the same required-credential behaviour as before:
	// a malformed response must fail here rather than propagate as a
	// credential that only fails at some later use.
	//
	// Seal before touching the receiver: decoding into a value that already
	// holds a password must not abandon that protected allocation, and must
	// not clear it if sealing fails.
	sealed, err := secrets.NewSecureStringFromBytes(context.Background(), raw.Password.Bytes())
	if err != nil {
		return err
	}
	c.Username = raw.Username
	c.Password.Destroy()
	c.Password = sealed
	return nil
}

// Destroy wipes the protected password. Safe on nil and idempotent.
func (c *DirectoryCredentials) Destroy() {
	if c == nil {
		return
	}
	c.Password.Destroy()
}
