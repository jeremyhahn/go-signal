package websocket

import (
	"encoding/base64"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// encodeEnvelopeBody serializes the envelope into its protobuf wire form and
// base64-encodes the result for the WebSocketRequest body field. The base64
// layer belongs to this struct's JSON representation only — codec.go decodes
// it back to raw bytes before the protobuf frame goes out, so what the client
// parses is exactly messages.MarshalEnvelope's output.
//
// Returns the empty string when the envelope cannot be marshalled. Callers
// must treat that as a failure to build the message rather than sending an
// empty body: a client parses zero bytes as an envelope with every field
// defaulted.
func encodeEnvelopeBody(envelope *messages.Envelope) string {
	data, err := messages.MarshalEnvelope(envelope)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}
