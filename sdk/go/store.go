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

	// Sticker packs (local registry of installed packs). The CLI's
	// addStickerPack command persists parsed pack URLs here so
	// subsequent getSticker calls can look up the pack key without
	// the operator re-typing it.
	GetStickerPacks() ([]InstalledStickerPack, error)
	SaveStickerPack(pack *InstalledStickerPack) error
	DeleteStickerPack(packID string) error

	// Close releases any resources held by the store.
	Close() error
}

// InstalledStickerPack records one locally-known sticker pack. PackID
// is the 32-char hex identifier; PackKey is the 32-byte hex secret
// that decrypts pack payloads.
type InstalledStickerPack struct {
	PackID  string `json:"packId"`
	PackKey string `json:"packKey"`
	URL     string `json:"url,omitempty"`
	Title   string `json:"title,omitempty"`
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
