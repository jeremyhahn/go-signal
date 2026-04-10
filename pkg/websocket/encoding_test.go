package websocket

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

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

	encoded := encodeEnvelopeBody(envelope)
	if encoded == "" {
		t.Fatal("encodeEnvelopeBody returned empty string for valid envelope")
	}

	// Decode and verify roundtrip.
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("failed to base64 decode: %v", err)
	}

	var result messages.Envelope
	if err := json.Unmarshal(decoded, &result); err != nil {
		t.Fatalf("failed to unmarshal decoded envelope: %v", err)
	}

	if result.ID != 1 {
		t.Errorf("ID = %d, want %d", result.ID, 1)
	}
	if result.SourceUUID != "sender-uuid" {
		t.Errorf("SourceUUID = %q, want %q", result.SourceUUID, "sender-uuid")
	}
	if result.DestinationUUID != "dest-uuid" {
		t.Errorf("DestinationUUID = %q, want %q", result.DestinationUUID, "dest-uuid")
	}
}

func TestEncodeEnvelopeBody_MinimalEnvelope(t *testing.T) {
	envelope := &messages.Envelope{
		ID:                1,
		DestinationUUID:   "dest",
		DestinationDevice: 1,
	}

	encoded := encodeEnvelopeBody(envelope)
	if encoded == "" {
		t.Fatal("encodeEnvelopeBody returned empty string for minimal envelope")
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("failed to base64 decode: %v", err)
	}

	var result messages.Envelope
	if err := json.Unmarshal(decoded, &result); err != nil {
		t.Fatalf("failed to unmarshal decoded envelope: %v", err)
	}

	if result.DestinationUUID != "dest" {
		t.Errorf("DestinationUUID = %q, want %q", result.DestinationUUID, "dest")
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

	encoded := encodeEnvelopeBody(envelope)

	// Verify the output is valid base64.
	_, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Errorf("output is not valid base64: %v", err)
	}
}

func TestEncodeEnvelopeBody_AllEnvelopeTypes(t *testing.T) {
	types := []messages.EnvelopeType{
		messages.EnvelopeTypeCiphertext,
		messages.EnvelopeTypeKeyExchange,
		messages.EnvelopeTypePrekeyBundle,
		messages.EnvelopeTypeReceipt,
		messages.EnvelopeTypeUnidentifiedSender,
		messages.EnvelopeTypePlaintextContent,
	}

	for _, envType := range types {
		envelope := &messages.Envelope{
			ID:              1,
			Type:            envType,
			DestinationUUID: "dest",
		}

		encoded := encodeEnvelopeBody(envelope)
		if encoded == "" {
			t.Errorf("encodeEnvelopeBody returned empty for type %d", envType)
		}
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

	encoded := encodeEnvelopeBody(envelope)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("failed to base64 decode: %v", err)
	}

	var result messages.Envelope
	if err := json.Unmarshal(decoded, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.ServerGUID != "server-guid-123" {
		t.Errorf("ServerGUID = %q, want %q", result.ServerGUID, "server-guid-123")
	}
	if !result.Urgent {
		t.Error("Urgent = false, want true")
	}
	if !result.Story {
		t.Error("Story = false, want true")
	}
	if string(result.ReportSpamToken) != "spam-token" {
		t.Errorf("ReportSpamToken = %q, want %q", result.ReportSpamToken, "spam-token")
	}
}
