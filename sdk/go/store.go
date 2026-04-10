package signal

import "github.com/jeremyhahn/go-signal/pkg/config/secrets"

// Store is the local persistence interface for the Signal client SDK.
// The default implementation is file-based (FileStore). When go-signal
// is embedded in go-quicbaas, a distributed implementation can be provided.
type Store interface {
	// Credentials
	GetCredentials() (*Credentials, error)
	SaveCredentials(creds *Credentials) error

	// Contacts
	GetContacts() ([]Contact, error)
	SaveContact(contact *Contact) error
	DeleteContact(number string) error

	// Messages
	GetMessages(conversationID string, limit int) ([]Message, error)
	SaveMessage(msg *Message) error

	// Groups
	GetGroups() ([]Group, error)
	SaveGroup(group *Group) error

	// Close releases any resources held by the store.
	Close() error
}

// Credentials holds the authentication state for a registered account.
// The Password field uses SecureString to prevent accidental leakage
// in logs, core dumps, or swap.
type Credentials struct {
	Number   string                `json:"number"`
	UUID     string                `json:"uuid"`
	PNI      string                `json:"pni,omitempty"`
	Password *secrets.SecureString `json:"-"` // Never serialized directly
	DeviceID uint32                `json:"deviceId"`
}

// Destroy wipes sensitive credential material.
func (c *Credentials) Destroy() {
	if c != nil && c.Password != nil {
		c.Password.Destroy()
	}
}
