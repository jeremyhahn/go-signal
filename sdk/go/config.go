// Package signal provides the Go SDK for the Signal messaging protocol.
// It is the public API for building Signal clients — CLI, GUI, or embedded.
//
// The SDK wraps go-libsignal for Signal Protocol cryptography and
// communicates with a go-signal server via REST and WebSocket APIs.
// All server URLs, certificates, and storage backends are configurable
// for self-hosted LAN and WAN deployments.
//
// All sensitive material (passwords, keys, certificates) is held in
// memguard-protected memory and zeroed on Close().
package signal

import (
	groupstore "github.com/jeremyhahn/go-libsignal/pkg/groups/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// ClientConfig holds all configuration for a Signal client connection.
// Sensitive fields use SecureString for memguard-protected memory.
type ClientConfig struct {
	// ServerURL is the base URL of the Signal server.
	ServerURL string

	// CACert is the PEM-encoded CA certificate for verifying the server's
	// TLS certificate. Held in secure memory to prevent leakage.
	CACert *secrets.SecureString

	// DataDir is the local directory for storing account data.
	DataDir string

	// Account is the phone number associated with this client.
	Account string

	// Password is the account authentication token. Held in secure memory
	// and never logged or serialized in plaintext.
	Password *secrets.SecureString

	// DeviceID is the device identifier (1 for primary device).
	DeviceID uint32

	// UserAgent is sent with all HTTP requests.
	UserAgent string

	// Store is an optional custom storage backend. When nil, a file-based
	// store is created in DataDir.
	Store Store

	// CryptoStores provides optional custom implementations of the
	// go-libsignal protocol stores. When nil, file-based stores in
	// DataDir are used. Desktop clients inject DAO-backed stores.
	CryptoStores *CryptoStoreConfig

	// OnMessage is called when a message is received via WebSocket.
	OnMessage func(msg ReceivedMessage)

	// OnTyping is called when a typing indicator is received.
	OnTyping func(sender string, started bool)

	// OnReceipt is called when a delivery/read receipt is received.
	OnReceipt func(sender string, timestamps []int64, receiptType string)

	// OnError is called when a background error occurs (e.g., WebSocket disconnect).
	OnError func(err error)

	// Verbose enables debug logging.
	Verbose bool
}

// CryptoStoreConfig holds optional custom implementations of the
// go-libsignal protocol stores. When provided in ClientConfig, these
// replace the default file-based stores.
type CryptoStoreConfig struct {
	SessionStore      store.Session
	PreKeyStore       store.PreKey
	SignedPreKeyStore  store.SignedPreKey
	IdentityStore     store.IdentityKey
	SenderKeyStore    groupstore.SenderKey
}

// Destroy wipes all sensitive material from the config. Called by Client.Close().
func (c *ClientConfig) Destroy() {
	if c.Password != nil {
		c.Password.Destroy()
	}
	if c.CACert != nil {
		c.CACert.Destroy()
	}
}
