package websocket

import (
	"encoding/base64"
	"encoding/json"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// encodeEnvelopeBody serializes the envelope as JSON and then base64-encodes
// the result for transmission in a WebSocketRequest body field.
func encodeEnvelopeBody(envelope *messages.Envelope) string {
	data, err := json.Marshal(envelope)
	if err != nil {
		// Envelope types are always serializable; a marshal failure here
		// indicates a programming error rather than a runtime condition.
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}
