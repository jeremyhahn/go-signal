package messages

import (
	"encoding/json"
	"testing"
)

func TestEnvelopeType_Constants(t *testing.T) {
	tests := []struct {
		name     string
		value    EnvelopeType
		expected int32
	}{
		{"Ciphertext", EnvelopeTypeCiphertext, 1},
		{"KeyExchange", EnvelopeTypeKeyExchange, 2},
		{"PrekeyBundle", EnvelopeTypePrekeyBundle, 3},
		{"Receipt", EnvelopeTypeReceipt, 5},
		{"UnidentifiedSender", EnvelopeTypeUnidentifiedSender, 6},
		{"PlaintextContent", EnvelopeTypePlaintextContent, 8},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if int32(tc.value) != tc.expected {
				t.Errorf("expected %d, got %d", tc.expected, int32(tc.value))
			}
		})
	}
}

func TestEnvelopeType_Uniqueness(t *testing.T) {
	values := []EnvelopeType{
		EnvelopeTypeCiphertext,
		EnvelopeTypeKeyExchange,
		EnvelopeTypePrekeyBundle,
		EnvelopeTypeReceipt,
		EnvelopeTypeUnidentifiedSender,
		EnvelopeTypePlaintextContent,
	}
	seen := make(map[EnvelopeType]bool)
	for _, v := range values {
		if seen[v] {
			t.Errorf("duplicate EnvelopeType value: %d", v)
		}
		seen[v] = true
	}
}

func TestEnvelope_ZeroValue(t *testing.T) {
	var e Envelope
	if e.ID != 0 {
		t.Errorf("expected zero ID, got %d", e.ID)
	}
	if e.Type != 0 {
		t.Errorf("expected zero Type, got %d", e.Type)
	}
	if e.SourceUUID != "" {
		t.Errorf("expected empty SourceUUID, got %q", e.SourceUUID)
	}
	if e.Content != nil {
		t.Errorf("expected nil Content, got %v", e.Content)
	}
	if e.Urgent {
		t.Error("expected Urgent to be false")
	}
	if e.Story {
		t.Error("expected Story to be false")
	}
}

func TestEnvelope_JSONRoundTrip(t *testing.T) {
	env := Envelope{
		ID:                1,
		Type:              EnvelopeTypeCiphertext,
		SourceUUID:        "src-uuid",
		SourceDevice:      1,
		DestinationUUID:   "dst-uuid",
		DestinationDevice: 2,
		Timestamp:         1000,
		ServerTimestamp:   2000,
		Content:           []byte{0x01, 0x02},
		ServerGUID:        "server-guid-1",
		Urgent:            true,
		Story:             false,
		ReportSpamToken:   []byte{0xFF},
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded Envelope
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.ID != env.ID {
		t.Errorf("ID mismatch: expected %d, got %d", env.ID, decoded.ID)
	}
	if decoded.Type != env.Type {
		t.Errorf("Type mismatch: expected %d, got %d", env.Type, decoded.Type)
	}
	if decoded.SourceUUID != env.SourceUUID {
		t.Errorf("SourceUUID mismatch: expected %q, got %q", env.SourceUUID, decoded.SourceUUID)
	}
	if decoded.DestinationUUID != env.DestinationUUID {
		t.Errorf("DestinationUUID mismatch")
	}
	if decoded.ServerGUID != env.ServerGUID {
		t.Errorf("ServerGUID mismatch")
	}
	if !decoded.Urgent {
		t.Error("expected Urgent to be true")
	}
}

func TestEnvelope_OmitsEmptyOptionalFields(t *testing.T) {
	env := Envelope{
		ID:                1,
		Type:              EnvelopeTypeCiphertext,
		DestinationUUID:   "dst",
		DestinationDevice: 1,
		Timestamp:         1000,
		ServerTimestamp:   2000,
		Content:           []byte{0x01},
		ServerGUID:        "guid",
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	m := make(map[string]interface{})
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}
	if _, ok := m["sourceUuid"]; ok {
		t.Error("expected sourceUuid to be omitted when empty")
	}
	if _, ok := m["reportSpamToken"]; ok {
		t.Error("expected reportSpamToken to be omitted when nil")
	}
}

func TestIncomingMessage_ZeroValue(t *testing.T) {
	var m IncomingMessage
	if m.Type != 0 {
		t.Errorf("expected zero Type, got %d", m.Type)
	}
	if m.DestinationUUID != "" {
		t.Errorf("expected empty DestinationUUID, got %q", m.DestinationUUID)
	}
	if m.Content != "" {
		t.Errorf("expected empty Content, got %q", m.Content)
	}
}

func TestIncomingMessage_JSONRoundTrip(t *testing.T) {
	msg := IncomingMessage{
		Type:                EnvelopeTypePrekeyBundle,
		DestinationUUID:     "dst-uuid",
		DestinationDeviceID: 3,
		Content:             "base64content",
		Timestamp:           5000,
		Urgent:              true,
		Story:               true,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded IncomingMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.Type != EnvelopeTypePrekeyBundle {
		t.Errorf("expected type %d, got %d", EnvelopeTypePrekeyBundle, decoded.Type)
	}
	if decoded.DestinationUUID != "dst-uuid" {
		t.Errorf("expected dst-uuid, got %q", decoded.DestinationUUID)
	}
	if !decoded.Story {
		t.Error("expected Story to be true")
	}
}

func TestIncomingMessageList_ZeroValue(t *testing.T) {
	var ml IncomingMessageList
	if ml.Messages != nil {
		t.Errorf("expected nil Messages, got %v", ml.Messages)
	}
	if ml.Timestamp != 0 {
		t.Errorf("expected zero Timestamp, got %d", ml.Timestamp)
	}
}

func TestIncomingMessageList_JSONRoundTrip(t *testing.T) {
	ml := IncomingMessageList{
		Messages: []IncomingMessage{
			{Type: EnvelopeTypeCiphertext, DestinationUUID: "uuid-1", DestinationDeviceID: 1, Content: "c1", Timestamp: 100},
			{Type: EnvelopeTypeCiphertext, DestinationUUID: "uuid-1", DestinationDeviceID: 2, Content: "c2", Timestamp: 100},
		},
		Timestamp: 100,
	}
	data, err := json.Marshal(ml)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded IncomingMessageList
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(decoded.Messages) != 2 {
		t.Errorf("expected 2 messages, got %d", len(decoded.Messages))
	}
	if decoded.Timestamp != 100 {
		t.Errorf("expected timestamp 100, got %d", decoded.Timestamp)
	}
}

func TestOutgoingMessage_ZeroValue(t *testing.T) {
	var m OutgoingMessage
	if m.DestinationUUID != "" {
		t.Errorf("expected empty DestinationUUID, got %q", m.DestinationUUID)
	}
	if m.Content != nil {
		t.Errorf("expected nil Content, got %v", m.Content)
	}
}

func TestOutgoingMessage_JSONRoundTrip(t *testing.T) {
	msg := OutgoingMessage{
		DestinationUUID:   "dst",
		DestinationDevice: 1,
		Type:              EnvelopeTypeUnidentifiedSender,
		Content:           []byte{0xAA, 0xBB},
		Timestamp:         9999,
		Urgent:            true,
		Story:             false,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded OutgoingMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.DestinationUUID != "dst" {
		t.Errorf("expected 'dst', got %q", decoded.DestinationUUID)
	}
	if decoded.Type != EnvelopeTypeUnidentifiedSender {
		t.Errorf("expected type %d, got %d", EnvelopeTypeUnidentifiedSender, decoded.Type)
	}
}

func TestSendMessageResponse_ZeroValue(t *testing.T) {
	var r SendMessageResponse
	if r.NeedsSync {
		t.Error("expected NeedsSync to be false")
	}
}

func TestSendMessageResponse_JSONRoundTrip(t *testing.T) {
	resp := SendMessageResponse{NeedsSync: true}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	var decoded SendMessageResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if !decoded.NeedsSync {
		t.Error("expected NeedsSync to be true")
	}
}
