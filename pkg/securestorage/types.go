package securestorage

import (
	"encoding/json"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// StorageCredentials are secure-storage credentials; Password is held in protected memory and MarshalJSON emits the plaintext to the client.
type StorageCredentials struct {
	Username string
	Password *secrets.SecureString
}

// Destroy wipes the protected password. Safe on nil and idempotent.
func (c *StorageCredentials) Destroy() {
	if c == nil {
		return
	}
	c.Password.Destroy()
}

// Compile-time check that the credential serialises through secrets.JSONAppender.
var _ secrets.JSONAppender = StorageCredentials{}

// AppendJSON writes {"username":…,"password":…} into a buffer the caller owns and wipes; writeJSON uses it.
func (c StorageCredentials) AppendJSON(dst []byte) ([]byte, error) {
	// The password goes from protected memory into dst; the username goes through encoding/json, in the original field order.
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

// MarshalJSON keeps the wire form for nested values; its buffer holds the plaintext unwiped, so responses use AppendJSON.
func (c StorageCredentials) MarshalJSON() ([]byte, error) {
	return c.AppendJSON(nil)
}

// UnmarshalJSON implements encoding/json.Unmarshaler so a credential that
// crossed the wire lands back in protected memory rather than a heap string.
func (c *StorageCredentials) UnmarshalJSON(data []byte) error {
	// secrets.JSONStringBytes keeps the password out of an unwipeable string and rejects wrong-typed duplicates.
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
	// An absent or empty password fails at sealing; seal before touching the receiver.
	sealed, err := secrets.NewSecureStringFromBytes(raw.Password.Bytes())
	if err != nil {
		return err
	}
	c.Username = raw.Username
	c.Password.Destroy()
	c.Password = sealed
	return nil
}
