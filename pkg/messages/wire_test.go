package messages

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	textsecurepb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/textsecure"
)

// roundTrip marshals an envelope and parses it back the way a client does.
func roundTrip(t *testing.T, env *Envelope) *textsecurepb.Envelope {
	t.Helper()
	raw, err := MarshalEnvelope(env)
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	var pb textsecurepb.Envelope
	if err := proto.Unmarshal(raw, &pb); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	return &pb
}

func TestMarshalEnvelope_MapsEveryWireField(t *testing.T) {
	env := &Envelope{
		ID:              7,
		Type:            EnvelopeTypeUnidentifiedSender,
		SourceUUID:      "11111111-1111-1111-1111-111111111111",
		SourceDevice:    3,
		DestinationUUID: "22222222-2222-2222-2222-222222222222",
		Timestamp:       1700000000123,
		ServerTimestamp: 1700000000456,
		Content:         []byte{0x00, 0x01, 0xff},
		ServerGUID:      "33333333-3333-3333-3333-333333333333",
		Urgent:          true,
		Story:           true,
		ReportSpamToken: []byte("spam"),
		SharedMrmKey:    []byte("mrm"),
	}

	pb := roundTrip(t, env)

	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"type", pb.GetType(), textsecurepb.Envelope_UNIDENTIFIED_SENDER},
		{"source_service_id", pb.GetSourceServiceId(), env.SourceUUID},
		{"source_device", pb.GetSourceDevice(), env.SourceDevice},
		{"destination_service_id", pb.GetDestinationServiceId(), env.DestinationUUID},
		{"client_timestamp", pb.GetClientTimestamp(), env.Timestamp},
		{"server_timestamp", pb.GetServerTimestamp(), env.ServerTimestamp},
		{"server_guid", pb.GetServerGuid(), env.ServerGUID},
		{"content", string(pb.GetContent()), string(env.Content)},
		{"urgent", pb.GetUrgent(), env.Urgent},
		{"story", pb.GetStory(), env.Story},
		{"report_spam_token", string(pb.GetReportSpamToken()), string(env.ReportSpamToken)},
		{"shared_mrm_key", string(pb.GetSharedMrmKey()), string(env.SharedMrmKey)},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}
}

// Absent values must stay absent on the wire. Emitting "" or 0 for an unset
// optional field is visible to the client as a present-but-empty value.
func TestMarshalEnvelope_OmitsUnsetOptionalFields(t *testing.T) {
	pb := roundTrip(t, &Envelope{
		Type:            EnvelopeTypeCiphertext,
		DestinationUUID: "dest",
	})

	if pb.SourceServiceId != nil {
		t.Errorf("source_service_id should be absent, got %q", pb.GetSourceServiceId())
	}
	if pb.SourceDevice != nil {
		t.Errorf("source_device should be absent, got %d", pb.GetSourceDevice())
	}
	if pb.ServerGuid != nil {
		t.Errorf("server_guid should be absent, got %q", pb.GetServerGuid())
	}
	if pb.Content != nil {
		t.Errorf("content should be absent, got %q", pb.GetContent())
	}
	// Java clears ephemeral in serializeMessage; we never set it.
	if pb.Ephemeral != nil {
		t.Errorf("ephemeral should be absent, got %v", pb.GetEphemeral())
	}
}

func TestMarshalEnvelope_TypeMapping(t *testing.T) {
	for envType, want := range map[EnvelopeType]textsecurepb.Envelope_Type{
		EnvelopeTypeCiphertext:         textsecurepb.Envelope_CIPHERTEXT,
		EnvelopeTypePrekeyBundle:       textsecurepb.Envelope_PREKEY_BUNDLE,
		EnvelopeTypeReceipt:            textsecurepb.Envelope_SERVER_DELIVERY_RECEIPT,
		EnvelopeTypeUnidentifiedSender: textsecurepb.Envelope_UNIDENTIFIED_SENDER,
		EnvelopeTypePlaintextContent:   textsecurepb.Envelope_PLAINTEXT_CONTENT,
	} {
		pb := roundTrip(t, &Envelope{Type: envType, DestinationUUID: "dest"})
		if pb.GetType() != want {
			t.Errorf("type %d encoded as %v, want %v", envType, pb.GetType(), want)
		}
	}
}

// Urgent defaults to true in the proto, so false must be written explicitly
// rather than omitted — an omitted field would read back as true.
func TestMarshalEnvelope_NonUrgentIsExplicit(t *testing.T) {
	pb := roundTrip(t, &Envelope{
		Type:            EnvelopeTypeCiphertext,
		DestinationUUID: "dest",
		Urgent:          false,
	})

	if pb.Urgent == nil {
		t.Fatal("urgent must be set explicitly; the proto default is true")
	}
	if pb.GetUrgent() {
		t.Error("urgent = true, want false")
	}
}

// A type the wire cannot represent must be refused, not downgraded. Encoding
// it as UNKNOWN would deliver a semantically different envelope and report
// success, so neither the sender nor the recipient could tell.
func TestMarshalEnvelope_RejectsUnrepresentableTypes(t *testing.T) {
	for _, envType := range []EnvelopeType{
		0,                       // unset — the field was never populated
		EnvelopeTypeKeyExchange, // 2, reserved in textsecure.proto
		7,                       // reserved in textsecure.proto
		99,                      // outside the enum entirely
	} {
		raw, err := MarshalEnvelope(&Envelope{Type: envType, DestinationUUID: "dest"})

		var unsupported *UnsupportedEnvelopeTypeError
		if !errors.As(err, &unsupported) {
			t.Errorf("type %d: expected *UnsupportedEnvelopeTypeError, got %#v", envType, err)
			continue
		}
		if unsupported.Type != envType {
			t.Errorf("error reports type %d, want %d", unsupported.Type, envType)
		}
		if raw != nil {
			t.Errorf("type %d: expected no bytes on error, got %d", envType, len(raw))
		}
	}
}

func TestMarshalEnvelope_NilEnvelope(t *testing.T) {
	raw, err := MarshalEnvelope(nil)

	var nilErr *NilEnvelopeError
	if !errors.As(err, &nilErr) {
		t.Fatalf("expected *NilEnvelopeError, got %#v", err)
	}
	if raw != nil {
		t.Errorf("expected no bytes on error, got %d", len(raw))
	}
}

// The output must not be JSON. This is the regression the whole change exists
// for: a JSON body base64s cleanly and looks fine until a client parses it.
func TestMarshalEnvelope_IsNotJSON(t *testing.T) {
	raw, err := MarshalEnvelope(&Envelope{
		Type:            EnvelopeTypeCiphertext,
		DestinationUUID: "dest",
		Content:         []byte("hello"),
	})
	if err != nil {
		t.Fatalf("MarshalEnvelope: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("no bytes produced")
	}
	if raw[0] == '{' {
		t.Error("body starts with '{' — this is JSON, not a protobuf envelope")
	}
}
