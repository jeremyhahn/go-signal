package securevaluerecovery

import (
	"encoding/json"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// SVRCredentials contains authentication credentials for the secure value
// recovery service.
//
// Password is the SVR bearer credential and is held in protected memory
// between issuance and serialization. The client is the intended bearer, so
// MarshalJSON deliberately opens the secret and emits the plaintext — the
// protection here is memory residency, not egress. That is why this type
// carries an explicit marshaller instead of relying on SecureString's
// default, which redacts.
type SVRCredentials struct {
	Username string
	Password *secrets.SecureString
}

// svrCredentialsJSON is the wire shape of SVRCredentials. It is
// byte-identical to what the plain-string struct produced, so SVR clients
// see no change.
type svrCredentialsJSON struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// MarshalJSON implements encoding/json.Marshaler, emitting the credential in
// the Signal-compatible `{"username":…,"password":…}` shape.
func (c SVRCredentials) MarshalJSON() ([]byte, error) {
	// Reveal, not Plaintext: a password that is unset or already wiped must
	// fail the response rather than hand the client an empty credential it
	// would treat as valid.
	password, err := c.Password.Reveal()
	if err != nil {
		return nil, err
	}
	return json.Marshal(svrCredentialsJSON{
		Username: c.Username,
		Password: password,
	})
}

// UnmarshalJSON implements encoding/json.Unmarshaler so a credential that
// crossed the wire lands back in protected memory rather than a heap string.
func (c *SVRCredentials) UnmarshalJSON(data []byte) error {
	var raw svrCredentialsJSON
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
func (c *SVRCredentials) Destroy() {
	if c == nil {
		return
	}
	c.Password.Destroy()
}

// AuthCheckRequest is the JSON body for checking SVR auth credentials.
type AuthCheckRequest struct {
	Passwords []string `json:"passwords"`
}

// AuthCheckResponse reports the match status for each submitted password.
type AuthCheckResponse struct {
	Matches map[string]string `json:"matches"`
}
