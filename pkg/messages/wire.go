package messages

import (
	"google.golang.org/protobuf/proto"

	textsecurepb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/textsecure"
)

// envelopeTypes maps internal envelope types to the textsecure.proto enum; an unmapped type is an error, never UNKNOWN.
var envelopeTypes = map[EnvelopeType]textsecurepb.Envelope_Type{
	EnvelopeTypeCiphertext:         textsecurepb.Envelope_CIPHERTEXT,
	EnvelopeTypePrekeyBundle:       textsecurepb.Envelope_PREKEY_BUNDLE,
	EnvelopeTypeReceipt:            textsecurepb.Envelope_SERVER_DELIVERY_RECEIPT,
	EnvelopeTypeUnidentifiedSender: textsecurepb.Envelope_UNIDENTIFIED_SENDER,
	EnvelopeTypePlaintextContent:   textsecurepb.Envelope_PLAINTEXT_CONTENT,
}

// MarshalEnvelope encodes the textsecure.Envelope protobuf clients read from PUT /api/v1/message; types without a wire value are rejected.
// ID, DestinationDevice, DestinationIdentityType and SharedMrmRecipientView are not sent; ephemeral is never set.
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
