package directory

import "github.com/jeremyhahn/go-signal/pkg/config/secrets"

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

// Destroy wipes the protected password. Safe on nil and idempotent.
func (c *DirectoryCredentials) Destroy() {
	if c == nil {
		return
	}
	c.Password.Destroy()
}
