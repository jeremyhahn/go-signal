package securevaluerecovery

import "github.com/jeremyhahn/go-signal/pkg/config/secrets"

// SVRCredentials contains authentication credentials for the secure value
// recovery service.
//
// Password is the SVR bearer credential and is held in protected memory
// between issuance and the response that hands it to its bearer. The type has
// no JSON form of its own: opening the secret takes a context, which a
// marshaller has no way to receive, so the REST layer reveals it under the
// request's context and writes the wire shape itself. Marshalled directly,
// Password falls back to SecureString's redacting marshaller.
type SVRCredentials struct {
	Username string
	Password *secrets.SecureString
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
