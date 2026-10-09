package securestorage

import "github.com/jeremyhahn/go-signal/pkg/config/secrets"

// StorageCredentials contains authentication credentials for the secure
// storage service.
//
// Password is the storage-service bearer credential and is held in protected
// memory between issuance and the response that hands it to its bearer. The
// type has no JSON form of its own: opening the secret takes a context, which
// a marshaller has no way to receive, so the REST layer reveals it under the
// request's context and writes the wire shape itself. Marshalled directly,
// Password falls back to SecureString's redacting marshaller.
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
