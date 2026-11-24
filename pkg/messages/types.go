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

// Envelope is an encrypted message awaiting delivery; DestinationIdentityType (zero is ACI) selects whether DestinationUUID is an ACI or PNI, stored under separate keys.
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

	// SharedMrmKey names the MRM cache row holding this envelope's shared payload; Content is empty and filled in at read time.
	SharedMrmKey []byte `json:"sharedMrmKey,omitempty"`

	// SharedMrmRecipientView is the 18-byte field (see SharedMRMViewKey) selecting this recipient's view in the SharedMrmKey hash.
	SharedMrmRecipientView []byte `json:"sharedMrmRecipientView,omitempty"`
}

// IncomingMessage is one client-submitted message for a device; DestinationIdentityType (zero is ACI) says whether DestinationUUID is an ACI or PNI.
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
