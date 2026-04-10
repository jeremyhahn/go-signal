// Package messages provides message types and storage interfaces for the Signal server.
package messages

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
type Envelope struct {
	ID                uint64       `json:"id"`
	Type              EnvelopeType `json:"type"`
	SourceUUID        string       `json:"sourceUuid,omitempty"`
	SourceDevice      uint32       `json:"sourceDevice,omitempty"`
	DestinationUUID   string       `json:"destinationUuid"`
	DestinationDevice uint64       `json:"destinationDevice"`
	Timestamp         uint64       `json:"timestamp"`
	ServerTimestamp   uint64       `json:"serverTimestamp"`
	Content           []byte       `json:"content"`
	ServerGUID        string       `json:"serverGuid"`
	Urgent            bool         `json:"urgent"`
	Story             bool         `json:"story"`
	ReportSpamToken   []byte       `json:"reportSpamToken,omitempty"`
}

// IncomingMessage represents a single message submitted by a sending client
// destined for a specific device.
type IncomingMessage struct {
	Type                EnvelopeType `json:"type"`
	DestinationUUID     string       `json:"destinationUuid"`
	DestinationDeviceID uint64       `json:"destinationDeviceId"`
	Content             string       `json:"content"`
	Timestamp           uint64       `json:"timestamp"`
	Urgent              bool         `json:"urgent"`
	Story               bool         `json:"story"`
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
