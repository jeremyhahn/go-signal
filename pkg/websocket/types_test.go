package websocket

import (
	"encoding/json"
	"testing"
)

func TestWebSocketMessage_MarshalRequest(t *testing.T) {
	msg := WebSocketMessage{
		Type: "request",
		Request: &WebSocketRequest{
			ID:   1,
			Verb: "GET",
			Path: "/api/v1/keepalive",
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded WebSocketMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Type != "request" {
		t.Errorf("Type = %q, want %q", decoded.Type, "request")
	}
	if decoded.Request == nil {
		t.Fatal("Request is nil after roundtrip")
	}
	if decoded.Request.ID != 1 {
		t.Errorf("Request.ID = %d, want %d", decoded.Request.ID, 1)
	}
	if decoded.Request.Verb != "GET" {
		t.Errorf("Request.Verb = %q, want %q", decoded.Request.Verb, "GET")
	}
	if decoded.Request.Path != "/api/v1/keepalive" {
		t.Errorf("Request.Path = %q, want %q", decoded.Request.Path, "/api/v1/keepalive")
	}
	if decoded.Response != nil {
		t.Error("Response should be nil for request message")
	}
}

func TestWebSocketMessage_MarshalResponse(t *testing.T) {
	msg := WebSocketMessage{
		Type: "response",
		Response: &WebSocketResponse{
			ID:      42,
			Status:  200,
			Message: "OK",
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded WebSocketMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Type != "response" {
		t.Errorf("Type = %q, want %q", decoded.Type, "response")
	}
	if decoded.Response == nil {
		t.Fatal("Response is nil after roundtrip")
	}
	if decoded.Response.ID != 42 {
		t.Errorf("Response.ID = %d, want %d", decoded.Response.ID, 42)
	}
	if decoded.Response.Status != 200 {
		t.Errorf("Response.Status = %d, want %d", decoded.Response.Status, 200)
	}
	if decoded.Response.Message != "OK" {
		t.Errorf("Response.Message = %q, want %q", decoded.Response.Message, "OK")
	}
	if decoded.Request != nil {
		t.Error("Request should be nil for response message")
	}
}

func TestWebSocketMessage_OmitEmptyFields(t *testing.T) {
	msg := WebSocketMessage{
		Type: "request",
		Request: &WebSocketRequest{
			ID:   1,
			Verb: "GET",
			Path: "/test",
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	raw := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, exists := raw["response"]; exists {
		t.Error("response field should be omitted when nil")
	}
}

func TestWebSocketMessage_OmitEmptyResponseFields(t *testing.T) {
	msg := WebSocketMessage{
		Type: "response",
		Response: &WebSocketResponse{
			ID:     1,
			Status: 200,
		},
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	raw := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, exists := raw["request"]; exists {
		t.Error("request field should be omitted when nil")
	}
}

func TestWebSocketRequest_MarshalWithBody(t *testing.T) {
	req := WebSocketRequest{
		ID:   10,
		Verb: "PUT",
		Path: "/api/v1/message",
		Body: "dGVzdCBib2R5",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded WebSocketRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != 10 {
		t.Errorf("ID = %d, want %d", decoded.ID, 10)
	}
	if decoded.Body != "dGVzdCBib2R5" {
		t.Errorf("Body = %q, want %q", decoded.Body, "dGVzdCBib2R5")
	}
	if decoded.Headers["Content-Type"] != "application/json" {
		t.Errorf("Headers[Content-Type] = %q, want %q", decoded.Headers["Content-Type"], "application/json")
	}
}

func TestWebSocketRequest_OmitEmptyBodyAndHeaders(t *testing.T) {
	req := WebSocketRequest{
		ID:   1,
		Verb: "GET",
		Path: "/test",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	raw := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, exists := raw["body"]; exists {
		t.Error("body should be omitted when empty")
	}
	if _, exists := raw["headers"]; exists {
		t.Error("headers should be omitted when nil")
	}
}

func TestWebSocketResponse_MarshalWithAllFields(t *testing.T) {
	resp := WebSocketResponse{
		ID:      99,
		Status:  404,
		Message: "not found",
		Body:    "Ym9keQ==",
		Headers: map[string]string{
			"X-Custom": "value",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded WebSocketResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.ID != 99 {
		t.Errorf("ID = %d, want %d", decoded.ID, 99)
	}
	if decoded.Status != 404 {
		t.Errorf("Status = %d, want %d", decoded.Status, 404)
	}
	if decoded.Message != "not found" {
		t.Errorf("Message = %q, want %q", decoded.Message, "not found")
	}
	if decoded.Body != "Ym9keQ==" {
		t.Errorf("Body = %q, want %q", decoded.Body, "Ym9keQ==")
	}
	if decoded.Headers["X-Custom"] != "value" {
		t.Errorf("Headers[X-Custom] = %q, want %q", decoded.Headers["X-Custom"], "value")
	}
}

func TestWebSocketResponse_OmitEmptyFields(t *testing.T) {
	resp := WebSocketResponse{
		ID:     1,
		Status: 200,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	raw := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, exists := raw["message"]; exists {
		t.Error("message should be omitted when empty")
	}
	if _, exists := raw["body"]; exists {
		t.Error("body should be omitted when empty")
	}
	if _, exists := raw["headers"]; exists {
		t.Error("headers should be omitted when nil")
	}
}

func TestWebSocketMessage_UnmarshalFromJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantType  string
		wantReq   bool
		wantResp  bool
		wantError bool
	}{
		{
			name:     "valid request",
			input:    `{"type":"request","request":{"id":1,"verb":"GET","path":"/test"}}`,
			wantType: "request",
			wantReq:  true,
		},
		{
			name:     "valid response",
			input:    `{"type":"response","response":{"id":2,"status":200}}`,
			wantType: "response",
			wantResp: true,
		},
		{
			name:      "invalid json",
			input:     `{invalid`,
			wantError: true,
		},
		{
			name:     "empty type",
			input:    `{"type":""}`,
			wantType: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var msg WebSocketMessage
			err := json.Unmarshal([]byte(tt.input), &msg)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected unmarshal error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}
			if msg.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", msg.Type, tt.wantType)
			}
			if tt.wantReq && msg.Request == nil {
				t.Error("expected Request to be non-nil")
			}
			if tt.wantResp && msg.Response == nil {
				t.Error("expected Response to be non-nil")
			}
		})
	}
}

func TestWebSocketRequest_ZeroValue(t *testing.T) {
	var req WebSocketRequest
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal zero value: %v", err)
	}

	var decoded WebSocketRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal zero value: %v", err)
	}

	if decoded.ID != 0 {
		t.Errorf("ID = %d, want 0", decoded.ID)
	}
	if decoded.Verb != "" {
		t.Errorf("Verb = %q, want empty", decoded.Verb)
	}
	if decoded.Path != "" {
		t.Errorf("Path = %q, want empty", decoded.Path)
	}
}

func TestWebSocketResponse_ZeroValue(t *testing.T) {
	var resp WebSocketResponse
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal zero value: %v", err)
	}

	var decoded WebSocketResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal zero value: %v", err)
	}

	if decoded.ID != 0 {
		t.Errorf("ID = %d, want 0", decoded.ID)
	}
	if decoded.Status != 0 {
		t.Errorf("Status = %d, want 0", decoded.Status)
	}
}
