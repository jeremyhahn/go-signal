package websocket

import (
	"encoding/base64"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// encodeEnvelopeBody returns the base64 protobuf envelope for the request body, or "" when marshalling fails, which callers must treat as an error.
func encodeEnvelopeBody(envelope *messages.Envelope) string {
	data, err := messages.MarshalEnvelope(envelope)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}
