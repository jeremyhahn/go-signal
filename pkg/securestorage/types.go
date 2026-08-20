package securestorage

import (
	"encoding/json"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// StorageCredentials contains authentication credentials for the secure
// storage service.
//
// Password is the storage-service bearer credential and is held in protected
// memory between issuance and serialization. The client is the intended
// bearer, so MarshalJSON deliberately opens the secret and emits the
// plaintext — the protection here is memory residency, not egress. That is why
// this type carries an explicit marshaller instead of relying on
// SecureString's default, which redacts.
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

// storageCredentialsJSON is the wire shape of StorageCredentials. It is
// byte-identical to what the plain-string struct produced, so storage-service
// clients see no change.
type storageCredentialsJSON struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// MarshalJSON implements encoding/json.Marshaler, emitting the credential in
// the Signal-compatible `{"username":…,"password":…}` shape.
func (c StorageCredentials) MarshalJSON() ([]byte, error) {
	// Reveal, not Plaintext: a password that is unset or already wiped must
	// fail the response rather than hand the client an empty credential it
	// would treat as valid. writeJSON turns a marshal error into a 500, so
	// this is the fail-closed path end to end.
	password, err := c.Password.Reveal()
	if err != nil {
		return nil, err
	}
	return json.Marshal(storageCredentialsJSON{
		Username: c.Username,
		Password: password,
	})
}

// UnmarshalJSON implements encoding/json.Unmarshaler so a credential that
// crossed the wire lands back in protected memory rather than a heap string.
func (c *StorageCredentials) UnmarshalJSON(data []byte) error {
	var raw storageCredentialsJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	// NewSecureString, not the optional form: this is a required bearer
	// credential, so a missing or empty password is a malformed response and
	// must fail here rather than propagate as a credential that only fails at
	// some later use.
	//
	// Seal the replacement before touching the receiver: decoding into a value
	// that already holds a password must not abandon that protected
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
