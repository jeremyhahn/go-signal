// Package messages provides message types and storage interfaces for the Signal server.
package messages

import "github.com/jeremyhahn/go-signal/pkg/accounts"

// EnvelopeType identifies the cryptographic message type within an envelope.
type EnvelopeType int32

const (
	// EnvelopeTypeCiphertext is a standard Signal protocol ciphertext message
	// sent within an established session.
	EnvelopeTypeCiphertext EnvelopeType = 1

	// EnvelopeTypeKeyExchange is a key exchange message used during session
	// negotiation.
	EnvelopeTypeKeyExchange EnvelopeType = 2

	// EnvelopeTypePrekeyBundle is a pre-key bundle message used to establish
	// a new session asynchronously.
	EnvelopeTypePrekeyBundle EnvelopeType = 3

	// EnvelopeTypeReceipt is a delivery or read receipt.
	EnvelopeTypeReceipt EnvelopeType = 5

	// EnvelopeTypeUnidentifiedSender is a sealed-sender message where the
	// sender identity is encrypted within the message payload.
	EnvelopeTypeUnidentifiedSender EnvelopeType = 6

	// EnvelopeTypePlaintextContent is a plaintext content message used for
	// sender key distribution and similar protocol messages.
	EnvelopeTypePlaintextContent EnvelopeType = 8
)

// Envelope represents an encrypted message envelope stored on the server
// pending delivery to a destination device.
//
// DestinationIdentityType selects the namespace under which
// DestinationUUID should be interpreted: ACI or PNI. Messages sent to
// an ACI and messages sent to a PNI are routed through the same
// storage layer but live under distinct keys so devices reading under
// one identity never see messages addressed to the other.
//
// For backwards compatibility the zero value
// (accounts.IdentityTypeACI) is treated as "ACI" — existing senders
// that don't know about PNI continue to work unchanged.
type Envelope struct {
	ID                      uint64                `json:"id"`
	Type                    EnvelopeType          `json:"type"`
	SourceUUID              string                `json:"sourceUuid,omitempty"`
	SourceDevice            uint32                `json:"sourceDevice,omitempty"`
	DestinationUUID         string                `json:"destinationUuid"`
	DestinationIdentityType accounts.IdentityType `json:"destinationIdentityType,omitempty"`
	DestinationDevice       uint64                `json:"destinationDevice"`
	Timestamp               uint64                `json:"timestamp"`
	ServerTimestamp         uint64                `json:"serverTimestamp"`
	Content                 []byte                `json:"content"`
	ServerGUID              string                `json:"serverGuid"`
	Urgent                  bool                  `json:"urgent"`
	Story                   bool                  `json:"story"`
	ReportSpamToken         []byte                `json:"reportSpamToken,omitempty"`

	// SharedMrmKey, when non-nil, identifies a row in the MRM cache holding
	// the shared multi-recipient payload for this envelope. Content is empty
	// in this case; the reader-side join in MessagesManager.GetMessagesForDevice
	// fetches the joined `data` + recipient view from the cache and inlines
	// them into Content before delivery. Mirrors Java Signal-Server's
	// `Envelope.shared_mrm_key` field.
	SharedMrmKey []byte `json:"sharedMrmKey,omitempty"`

	// SharedMrmRecipientView, when non-nil, is the 18-byte cache-field name
	// (see SharedMRMViewKey) selecting this recipient's view from the shared
	// MRM hash referenced by SharedMrmKey. Set together with SharedMrmKey
	// during multi-recipient sends.
	SharedMrmRecipientView []byte `json:"sharedMrmRecipientView,omitempty"`
}

// IncomingMessage represents a single message submitted by a sending client
// destined for a specific device.
//
// DestinationIdentityType disambiguates whether DestinationUUID is an
// ACI or a PNI. The zero value (accounts.IdentityTypeACI) is the
// default so clients that pre-date PNI support continue to work.
type IncomingMessage struct {
	Type                    EnvelopeType          `json:"type"`
	DestinationUUID         string                `json:"destinationUuid"`
	DestinationIdentityType accounts.IdentityType `json:"destinationIdentityType,omitempty"`
	DestinationDeviceID     uint64                `json:"destinationDeviceId"`
	Content                 string                `json:"content"`
	Timestamp               uint64                `json:"timestamp"`
	Urgent                  bool                  `json:"urgent"`
	Story                   bool                  `json:"story"`
}

// IncomingMessageList is a batch of messages submitted by a sending client,
// typically one per destination device.
type IncomingMessageList struct {
	Messages  []IncomingMessage `json:"messages"`
	Timestamp uint64            `json:"timestamp"`
}

// OutgoingMessage represents a message being sent to a specific device.
type OutgoingMessage struct {
	DestinationUUID   string       `json:"destinationUuid"`
	DestinationDevice uint64       `json:"destinationDevice"`
	Type              EnvelopeType `json:"type"`
	Content           []byte       `json:"content"`
	Timestamp         uint64       `json:"timestamp"`
	Urgent            bool         `json:"urgent"`
	Story             bool         `json:"story"`
}

// SendMessageResponse is returned after successfully processing an incoming
// message batch.
type SendMessageResponse struct {
	NeedsSync bool `json:"needsSync"`
}
