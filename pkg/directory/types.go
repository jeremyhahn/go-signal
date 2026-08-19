package directory

import (
	"encoding/json"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// DirectoryCredentials contains authentication credentials for the contact
// discovery service.
//
// Password is the CDS bearer credential and is held in protected memory
// between issuance and serialization. The client is the intended bearer, so
// MarshalJSON deliberately opens the secret and emits the plaintext — the
// protection here is memory residency, not egress. That is why this type
// carries an explicit marshaller instead of relying on SecureString's
// default, which redacts.
type DirectoryCredentials struct {
	Username string
	Password *secrets.SecureString
}

// directoryCredentialsJSON is the wire shape of DirectoryCredentials. It is
// byte-identical to what the plain-string struct produced, so CDS clients
// see no change.
type directoryCredentialsJSON struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// MarshalJSON implements encoding/json.Marshaler, emitting the credential in
// the Signal-compatible `{"username":…,"password":…}` shape.
func (c DirectoryCredentials) MarshalJSON() ([]byte, error) {
	// Reveal, not Plaintext: a password that is unset or already wiped must
	// fail the response rather than hand the client an empty credential it
	// would treat as valid.
	password, err := c.Password.Reveal()
	if err != nil {
		return nil, err
	}
	return json.Marshal(directoryCredentialsJSON{
		Username: c.Username,
		Password: password,
	})
}

// UnmarshalJSON implements encoding/json.Unmarshaler so a credential that
// crossed the wire lands back in protected memory rather than a heap string.
func (c *DirectoryCredentials) UnmarshalJSON(data []byte) error {
	var raw directoryCredentialsJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// NewSecureString, not the optional form: this is a required bearer
	// credential, so a missing or empty password is a malformed response and
	// must fail here rather than propagate as a credential that only fails
	// at some later use.
	//
	// Seal the replacement before touching the receiver: decoding into a
	// value that already holds a password must not abandon that protected
	// allocation, and must not clear it if sealing fails.
	password, err := secrets.NewSecureString(raw.Password)
	if err != nil {
		return err
	}
	c.Username = raw.Username
	c.Password.Destroy()
	c.Password = password
	return nil
}

// Destroy wipes the protected password. Safe on nil and idempotent.
func (c *DirectoryCredentials) Destroy() {
	if c == nil {
		return
	}
	c.Password.Destroy()
}
