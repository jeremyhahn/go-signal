package websocket

import (
	"encoding/base64"
	"testing"

	"google.golang.org/protobuf/proto"

	textsecurepb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/textsecure"
	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// decodeBody reverses what encodeEnvelopeBody produces and parses the result
// the way a client does — as a textsecure.Envelope protobuf. These tests
// previously parsed it as JSON, which is precisely how the wire-format defect
// went unnoticed, so parsing as protobuf here is the point rather than an
// implementation detail.
func decodeBody(t *testing.T, encoded string) *textsecurepb.Envelope {
	t.Helper()
	if encoded == "" {
		t.Fatal("encodeEnvelopeBody returned an empty body")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("body is not valid base64: %v", err)
	}
	var pb textsecurepb.Envelope
	if err := proto.Unmarshal(raw, &pb); err != nil {
		t.Fatalf("body is not a parseable Envelope protobuf: %v", err)
	}
	return &pb
}

func TestEncodeEnvelopeBody_ValidEnvelope(t *testing.T) {
	envelope := &messages.Envelope{
		ID:              1,
		Type:            messages.EnvelopeTypeCiphertext,
		SourceUUID:      "sender-uuid",
		SourceDevice:    1,
		DestinationUUID: "dest-uuid",
		Timestamp:       1700000000,
		Content:         []byte("encrypted-content"),
	}

	pb := decodeBody(t, encodeEnvelopeBody(envelope))

	if pb.GetType() != textsecurepb.Envelope_CIPHERTEXT {
		t.Errorf("type = %v, want CIPHERTEXT", pb.GetType())
	}
	if pb.GetSourceServiceId() != "sender-uuid" {
		t.Errorf("source_service_id = %q, want %q", pb.GetSourceServiceId(), "sender-uuid")
	}
	if pb.GetSourceDevice() != 1 {
		t.Errorf("source_device = %d, want 1", pb.GetSourceDevice())
	}
	if pb.GetDestinationServiceId() != "dest-uuid" {
		t.Errorf("destination_service_id = %q, want %q", pb.GetDestinationServiceId(), "dest-uuid")
	}
	// Signal's wire field is client_timestamp, not "timestamp".
	if pb.GetClientTimestamp() != 1700000000 {
		t.Errorf("client_timestamp = %d, want 1700000000", pb.GetClientTimestamp())
	}
	if string(pb.GetContent()) != "encrypted-content" {
		t.Errorf("content = %q, want %q", pb.GetContent(), "encrypted-content")
	}
}

func TestEncodeEnvelopeBody_MinimalEnvelope(t *testing.T) {
	envelope := &messages.Envelope{
		ID:                1,
		Type:              messages.EnvelopeTypeCiphertext,
		DestinationUUID:   "dest",
		DestinationDevice: 1,
	}

	pb := decodeBody(t, encodeEnvelopeBody(envelope))

	if pb.GetDestinationServiceId() != "dest" {
		t.Errorf("destination_service_id = %q, want %q", pb.GetDestinationServiceId(), "dest")
	}
	// An unset source must stay absent rather than being sent as "".
	if pb.SourceServiceId != nil {
		t.Errorf("source_service_id should be absent, got %q", pb.GetSourceServiceId())
	}
}

func TestEncodeEnvelopeBody_OutputIsValidBase64(t *testing.T) {
	envelope := &messages.Envelope{
		ID:              42,
		Type:            messages.EnvelopeTypePrekeyBundle,
		SourceUUID:      "source",
		DestinationUUID: "destination",
		Content:         []byte{0x00, 0x01, 0x02, 0xff},
		Urgent:          true,
	}

	if _, err := base64.StdEncoding.DecodeString(encodeEnvelopeBody(envelope)); err != nil {
		t.Errorf("output is not valid base64: %v", err)
	}
}

func TestEncodeEnvelopeBody_AllEnvelopeTypes(t *testing.T) {
	// Every type the wire protocol declares maps to its own enum value.
	// EnvelopeTypeKeyExchange is deliberately absent: field 2 is reserved in
	// textsecure.proto, so it is sent as UNKNOWN — asserted separately below.
	want := map[messages.EnvelopeType]textsecurepb.Envelope_Type{
		messages.EnvelopeTypeCiphertext:         textsecurepb.Envelope_CIPHERTEXT,
		messages.EnvelopeTypePrekeyBundle:       textsecurepb.Envelope_PREKEY_BUNDLE,
		messages.EnvelopeTypeReceipt:            textsecurepb.Envelope_SERVER_DELIVERY_RECEIPT,
		messages.EnvelopeTypeUnidentifiedSender: textsecurepb.Envelope_UNIDENTIFIED_SENDER,
		messages.EnvelopeTypePlaintextContent:   textsecurepb.Envelope_PLAINTEXT_CONTENT,
	}

	for envType, wantPB := range want {
		pb := decodeBody(t, encodeEnvelopeBody(&messages.Envelope{
			ID:              1,
			Type:            envType,
			DestinationUUID: "dest",
		}))
		if pb.GetType() != wantPB {
			t.Errorf("envelope type %d encoded as %v, want %v", envType, pb.GetType(), wantPB)
		}
	}
}

// A reserved type has no wire representation, so the body cannot be built and
// the caller drops the delivery. Encoding it as UNKNOWN would hand the client
// a different kind of message than the sender sent.
func TestEncodeEnvelopeBody_ReservedTypeYieldsNoBody(t *testing.T) {
	got := encodeEnvelopeBody(&messages.Envelope{
		ID:              1,
		Type:            messages.EnvelopeTypeKeyExchange, // 2, reserved
		DestinationUUID: "dest",
	})

	if got != "" {
		t.Errorf("encodeEnvelopeBody for a reserved type = %q, want empty", got)
	}
}

func TestEncodeEnvelopeBody_WithOptionalFields(t *testing.T) {
	envelope := &messages.Envelope{
		ID:              100,
		Type:            messages.EnvelopeTypeCiphertext,
		SourceUUID:      "src",
		SourceDevice:    2,
		DestinationUUID: "dst",
		Timestamp:       9999999999,
		ServerTimestamp: 8888888888,
		Content:         []byte("content"),
		ServerGUID:      "server-guid-123",
		Urgent:          true,
		Story:           true,
		ReportSpamToken: []byte("spam-token"),
	}

	pb := decodeBody(t, encodeEnvelopeBody(envelope))

	if pb.GetServerGuid() != "server-guid-123" {
		t.Errorf("server_guid = %q, want %q", pb.GetServerGuid(), "server-guid-123")
	}
	if pb.GetServerTimestamp() != 8888888888 {
		t.Errorf("server_timestamp = %d, want 8888888888", pb.GetServerTimestamp())
	}
	if !pb.GetUrgent() {
		t.Error("urgent = false, want true")
	}
	if !pb.GetStory() {
		t.Error("story = false, want true")
	}
	if string(pb.GetReportSpamToken()) != "spam-token" {
		t.Errorf("report_spam_token = %q, want %q", pb.GetReportSpamToken(), "spam-token")
	}
	// Java clears ephemeral before sending; we never set it.
	if pb.Ephemeral != nil {
		t.Errorf("ephemeral should be absent, got %v", pb.GetEphemeral())
	}
}

func TestEncodeEnvelopeBody_NilEnvelopeReturnsEmpty(t *testing.T) {
	if got := encodeEnvelopeBody(nil); got != "" {
		t.Errorf("encodeEnvelopeBody(nil) = %q, want empty so the caller drops the delivery", got)
	}
}
