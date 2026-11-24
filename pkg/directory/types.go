package directory

import (
	"encoding/json"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// DirectoryCredentials are contact-discovery credentials; Password stays in protected memory until it is serialized for the client.
type DirectoryCredentials struct {
	Username string
	Password *secrets.SecureString
}

// Compile-time check that the credential serializes through the owned-buffer path.
var _ secrets.JSONAppender = DirectoryCredentials{}

// AppendJSON implements secrets.JSONAppender, writing {"username":…,"password":…} into a buffer the caller owns and wipes.
func (c DirectoryCredentials) AppendJSON(dst []byte) ([]byte, error) {
	// The password goes from protected memory straight into dst; field order keeps the wire form byte-identical.
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

	// An unset or wiped password fails the response; dst is returned for the caller to wipe.
	dst, err = c.Password.AppendJSONString(dst)
	if err != nil {
		return dst, err
	}
	// Grow before the closing brace: a bare append here could reallocate and
	// abandon the array holding the password, which nothing could then wipe.
	dst = secrets.Grow(dst, 1)
	return append(dst, '}'), nil
}

// MarshalJSON emits {"username":…,"password":…}; encoding/json leaves an unwiped copy, so production responses use AppendJSON.
func (c DirectoryCredentials) MarshalJSON() ([]byte, error) {
	return c.AppendJSON(nil)
}

// UnmarshalJSON implements encoding/json.Unmarshaler so a credential that
// crossed the wire lands back in protected memory rather than a heap string.
func (c *DirectoryCredentials) UnmarshalJSON(data []byte) error {
	// secrets.JSONStringBytes, not string, so the password never lands in unwipeable memory.
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
	// An absent or empty password fails sealing; seal before replacing the receiver's value.
	sealed, err := secrets.NewSecureStringFromBytes(raw.Password.Bytes())
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
