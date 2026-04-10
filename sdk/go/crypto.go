package signal

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	groupstore "github.com/jeremyhahn/go-libsignal/pkg/groups/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// cryptoState holds the go-libsignal stores and serializer for the client.
// Store fields use interfaces so both file-based and injected (e.g., DAO-backed)
// implementations work transparently.
type cryptoState struct {
	serializer        *serialize.Serializer
	sessionStore      store.Session
	preKeyStore       store.PreKey
	signedPreKeyStore store.SignedPreKey
	identityStore     store.IdentityKey
	senderKeyStore    groupstore.SenderKey
}

// initCrypto initializes the Signal Protocol crypto state for the client.
// When CryptoStores is set in the config, the provided stores are used
// directly (e.g., DAO-backed stores for the desktop client). Otherwise,
// file-based stores are created in DataDir.
func (c *Client) initCrypto() error {
	if c.crypto != nil {
		return nil
	}

	serializer := serialize.NewProtobufSerializer()

	// Use injected stores if provided.
	if cs := c.config.CryptoStores; cs != nil {
		c.crypto = &cryptoState{
			serializer:        serializer,
			sessionStore:      cs.SessionStore,
			preKeyStore:       cs.PreKeyStore,
			signedPreKeyStore: cs.SignedPreKeyStore,
			identityStore:     cs.IdentityStore,
			senderKeyStore:    cs.SenderKeyStore,
		}
		return nil
	}

	// Fall back to file-based stores.
	sessStore, err := newFileSessionStore(c.config.DataDir, serializer)
	if err != nil {
		return fmt.Errorf("init session store: %w", err)
	}

	preKeyStore, err := newFilePreKeyStore(c.config.DataDir)
	if err != nil {
		return fmt.Errorf("init pre-key store: %w", err)
	}

	signedPreKeyStore, err := newFileSignedPreKeyStore(c.config.DataDir)
	if err != nil {
		return fmt.Errorf("init signed pre-key store: %w", err)
	}

	senderKeyStore, err := newFileSenderKeyStore(c.config.DataDir)
	if err != nil {
		return fmt.Errorf("init sender key store: %w", err)
	}

	// Load identity key pair from the identity store. If none exists yet
	// (fresh registration), generate a new pair.
	var identityKeyPair *identity.KeyPair
	var regID uint32 = 1

	creds, _ := c.store.GetCredentials()
	if creds != nil {
		regID = creds.DeviceID
	}

	// Generate a fresh identity key pair for this client instance.
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	identityKeyPair = identity.NewKeyPair(pubKey, kp.PrivateKey())

	identityStore, err := newFileIdentityStore(c.config.DataDir, identityKeyPair, regID)
	if err != nil {
		return fmt.Errorf("init identity store: %w", err)
	}

	c.crypto = &cryptoState{
		serializer:        serializer,
		sessionStore:      sessStore,
		preKeyStore:       preKeyStore,
		signedPreKeyStore: signedPreKeyStore,
		identityStore:     identityStore,
		senderKeyStore:    senderKeyStore,
	}

	return nil
}

// ensureSession fetches a pre-key bundle from the server and establishes
// an encrypted session if one doesn't already exist.
func (c *Client) ensureSession(ctx context.Context, recipientUUID string, deviceID uint32) error {
	if err := c.initCrypto(); err != nil {
		return err
	}

	addr := protocol.NewSignalAddress(recipientUUID, deviceID)

	// Check if session already exists.
	if c.crypto.sessionStore.ContainsSession(addr) {
		return nil
	}

	// Fetch pre-key bundle from server.
	var bundleResp struct {
		IdentityKey string `json:"identityKey"`
		Devices     []struct {
			DeviceID       uint32 `json:"deviceId"`
			RegistrationID uint32 `json:"registrationId"`
			SignedPreKey   struct {
				KeyID     uint64 `json:"keyId"`
				PublicKey string `json:"publicKey"`
				Signature string `json:"signature"`
			} `json:"signedPreKey"`
			PreKey *struct {
				KeyID     uint64 `json:"keyId"`
				PublicKey string `json:"publicKey"`
			} `json:"preKey,omitempty"`
		} `json:"devices"`
	}

	path := fmt.Sprintf("/v2/keys/%s/%d", recipientUUID, deviceID)
	if err := c.doRequest(ctx, "GET", path, nil, &bundleResp); err != nil {
		return fmt.Errorf("fetch pre-key bundle: %w", err)
	}

	if len(bundleResp.Devices) == 0 {
		return fmt.Errorf("no devices found for %s", recipientUUID)
	}

	dev := bundleResp.Devices[0]

	// Decode identity key.
	identityKeyBytes, err := base64.StdEncoding.DecodeString(bundleResp.IdentityKey)
	if err != nil {
		return fmt.Errorf("decode identity key: %w", err)
	}
	identityPubKey, err := ecc.DecodePoint(identityKeyBytes, 0)
	if err != nil {
		return fmt.Errorf("decode identity public key: %w", err)
	}
	remoteIdentity := identity.NewKey(identityPubKey)

	// Decode signed pre-key.
	signedPKBytes, err := base64.StdEncoding.DecodeString(dev.SignedPreKey.PublicKey)
	if err != nil {
		return fmt.Errorf("decode signed pre-key: %w", err)
	}
	signedPK, err := ecc.DecodePoint(signedPKBytes, 0)
	if err != nil {
		return fmt.Errorf("decode signed pre-key point: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(dev.SignedPreKey.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	var sig [64]byte
	copy(sig[:], sigBytes)

	// Decode optional one-time pre-key.
	var preKeyID *optional.Uint32
	var preKeyPub ecc.ECPublicKeyable
	if dev.PreKey != nil {
		id := uint32(dev.PreKey.KeyID)
		preKeyID = optional.NewOptionalUint32(id)
		pkBytes, err := base64.StdEncoding.DecodeString(dev.PreKey.PublicKey)
		if err == nil {
			preKeyPub, _ = ecc.DecodePoint(pkBytes, 0)
		}
	}

	// Build bundle.
	bundle := prekey.NewBundle(
		dev.RegistrationID,
		dev.DeviceID,
		preKeyID,
		uint32(dev.SignedPreKey.KeyID),
		preKeyPub,
		signedPK,
		sig,
		remoteIdentity,
	)

	// Build session.
	builder := session.NewBuilder(
		c.crypto.sessionStore,
		c.crypto.preKeyStore,
		c.crypto.signedPreKeyStore,
		c.crypto.identityStore,
		addr,
		c.crypto.serializer,
	)

	if err := builder.ProcessBundle(bundle); err != nil {
		return fmt.Errorf("process pre-key bundle: %w", err)
	}

	return nil
}

// encryptMessage encrypts plaintext for the given recipient using
// the established Signal Protocol session.
func (c *Client) encryptMessage(recipientUUID string, deviceID uint32, plaintext []byte) (protocol.CiphertextMessage, error) {
	if err := c.initCrypto(); err != nil {
		return nil, err
	}

	addr := protocol.NewSignalAddress(recipientUUID, deviceID)

	builder := session.NewBuilder(
		c.crypto.sessionStore,
		c.crypto.preKeyStore,
		c.crypto.signedPreKeyStore,
		c.crypto.identityStore,
		addr,
		c.crypto.serializer,
	)

	cipher := session.NewCipher(builder, addr)
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	return ciphertext, nil
}

// decryptMessage decrypts an incoming Signal Protocol message.
func (c *Client) decryptMessage(senderUUID string, deviceID uint32, msgType int, content []byte) ([]byte, error) {
	if err := c.initCrypto(); err != nil {
		return nil, err
	}

	addr := protocol.NewSignalAddress(senderUUID, deviceID)

	builder := session.NewBuilder(
		c.crypto.sessionStore,
		c.crypto.preKeyStore,
		c.crypto.signedPreKeyStore,
		c.crypto.identityStore,
		addr,
		c.crypto.serializer,
	)

	cipher := session.NewCipher(builder, addr)

	switch msgType {
	case protocol.PREKEY_TYPE:
		// Pre-key message — first message in a new session.
		preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(
			content,
			c.crypto.serializer.PreKeySignalMessage,
			c.crypto.serializer.SignalMessage,
		)
		if err != nil {
			return nil, fmt.Errorf("deserialize pre-key message: %w", err)
		}
		plaintext, _, err := cipher.DecryptPreKeyMessage(builder, preKeyMsg)
		if err != nil {
			return nil, fmt.Errorf("decrypt pre-key message: %w", err)
		}
		return plaintext, nil

	case protocol.WHISPER_TYPE:
		// Normal ratchet message — established session.
		signalMsg, err := protocol.NewSignalMessageFromBytes(
			content,
			c.crypto.serializer.SignalMessage,
		)
		if err != nil {
			return nil, fmt.Errorf("deserialize signal message: %w", err)
		}
		plaintext, err := cipher.Decrypt(signalMsg)
		if err != nil {
			return nil, fmt.Errorf("decrypt signal message: %w", err)
		}
		return plaintext, nil

	default:
		// Plaintext or unsupported type — return raw content.
		return content, nil
	}
}
