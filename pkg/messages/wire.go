package messages

import (
	"google.golang.org/protobuf/proto"

	textsecurepb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/textsecure"
)

// envelopeTypes maps the internal envelope type onto the wire enum. Only the
// values textsecure.proto declares appear here; 2 (key exchange) and 7 are
// reserved on the wire and have no representation at all.
//
// A type absent from this map is an error, not a default. Coercing it to
// UNKNOWN would deliver a semantically different envelope while reporting
// success — the message arrives, is the wrong kind, and nothing anywhere
// records that a substitution happened.
var envelopeTypes = map[EnvelopeType]textsecurepb.Envelope_Type{
	EnvelopeTypeCiphertext:         textsecurepb.Envelope_CIPHERTEXT,
	EnvelopeTypePrekeyBundle:       textsecurepb.Envelope_PREKEY_BUNDLE,
	EnvelopeTypeReceipt:            textsecurepb.Envelope_SERVER_DELIVERY_RECEIPT,
	EnvelopeTypeUnidentifiedSender: textsecurepb.Envelope_UNIDENTIFIED_SENDER,
	EnvelopeTypePlaintextContent:   textsecurepb.Envelope_PLAINTEXT_CONTENT,
}

// MarshalEnvelope serializes an envelope into the `textsecure.Envelope`
// protobuf every Signal client expects in the body of
// `PUT /api/v1/message`. This is the only wire form of an envelope: a client
// parses these bytes with the generated protobuf reader, so any other
// encoding — JSON in particular — surfaces as a parse failure rather than as
// an empty inbox.
//
// An envelope whose type has no wire representation is rejected rather than
// downgraded; see envelopeTypes.
//
// Not every field of the internal Envelope crosses the wire. ID is the
// WebSocket request identifier, not envelope content; DestinationDevice and
// DestinationIdentityType are routing state the server has already acted on
// by this point; and SharedMrmRecipientView is resolved server-side into
// Content before delivery. `ephemeral` is never set, matching Java, which
// clears it in WebSocketConnection.serializeMessage.
func MarshalEnvelope(env *Envelope) ([]byte, error) {
	if env == nil {
		return nil, &NilEnvelopeError{}
	}

	envType, ok := envelopeTypes[env.Type]
	if !ok {
		return nil, &UnsupportedEnvelopeTypeError{Type: env.Type}
	}

	pb := &textsecurepb.Envelope{
		Type:            envType.Enum(),
		ClientTimestamp: proto.Uint64(env.Timestamp),
		ServerTimestamp: proto.Uint64(env.ServerTimestamp),
		Urgent:          proto.Bool(env.Urgent),
		Story:           proto.Bool(env.Story),
	}
	if env.SourceUUID != "" {
		pb.SourceServiceId = proto.String(env.SourceUUID)
	}
	if env.SourceDevice != 0 {
		pb.SourceDevice = proto.Uint32(env.SourceDevice)
	}
	if env.DestinationUUID != "" {
		pb.DestinationServiceId = proto.String(env.DestinationUUID)
	}
	if env.ServerGUID != "" {
		pb.ServerGuid = proto.String(env.ServerGUID)
	}
	if len(env.Content) > 0 {
		pb.Content = env.Content
	}
	if len(env.ReportSpamToken) > 0 {
		pb.ReportSpamToken = env.ReportSpamToken
	}
	if len(env.SharedMrmKey) > 0 {
		pb.SharedMrmKey = env.SharedMrmKey
	}

	return proto.Marshal(pb)
}
