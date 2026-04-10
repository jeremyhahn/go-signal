package websocket

import (
	"encoding/base64"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	pb "github.com/jeremyhahn/go-signal/pkg/websocket/wsproto"
)

func TestMarshalUnmarshalFrame_JSON_Roundtrip(t *testing.T) {
	msg := &WebSocketMessage{
		Type: "request",
		Request: &WebSocketRequest{
			ID:   42,
			Verb: "PUT",
			Path: "/v1/messages/abc",
			Body: base64.StdEncoding.EncodeToString([]byte("hello")),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
	}

	data, err := MarshalFrame(msg, FrameFormatJSON)
	if err != nil {
		t.Fatalf("MarshalFrame JSON: %v", err)
	}

	got, err := UnmarshalFrame(data, FrameFormatJSON)
	if err != nil {
		t.Fatalf("UnmarshalFrame JSON: %v", err)
	}

	if got.Type != "request" {
		t.Errorf("Type = %q, want %q", got.Type, "request")
	}
	if got.Request.ID != 42 {
		t.Errorf("ID = %d, want %d", got.Request.ID, 42)
	}
	if got.Request.Verb != "PUT" {
		t.Errorf("Verb = %q, want %q", got.Request.Verb, "PUT")
	}
	if got.Request.Path != "/v1/messages/abc" {
		t.Errorf("Path = %q, want %q", got.Request.Path, "/v1/messages/abc")
	}
}

func TestMarshalUnmarshalFrame_Protobuf_Roundtrip(t *testing.T) {
	msg := &WebSocketMessage{
		Type: "request",
		Request: &WebSocketRequest{
			ID:   7,
			Verb: "PUT",
			Path: "/v1/messages/dest-uuid",
			Body: base64.StdEncoding.EncodeToString([]byte("encrypted-content")),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
	}

	data, err := MarshalFrame(msg, FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("MarshalFrame protobuf: %v", err)
	}

	// Verify it's valid protobuf.
	var pbMsg pb.WebSocketMessage
	if err := proto.Unmarshal(data, &pbMsg); err != nil {
		t.Fatalf("data is not valid protobuf: %v", err)
	}
	if pbMsg.GetType() != pb.WebSocketMessage_REQUEST {
		t.Errorf("protobuf type = %v, want REQUEST", pbMsg.GetType())
	}

	// Unmarshal back through our codec.
	got, err := UnmarshalFrame(data, FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("UnmarshalFrame protobuf: %v", err)
	}

	if got.Type != "request" {
		t.Errorf("Type = %q, want %q", got.Type, "request")
	}
	if got.Request.ID != 7 {
		t.Errorf("ID = %d, want %d", got.Request.ID, 7)
	}
	if got.Request.Verb != "PUT" {
		t.Errorf("Verb = %q, want %q", got.Request.Verb, "PUT")
	}
	if got.Request.Path != "/v1/messages/dest-uuid" {
		t.Errorf("Path = %q, want %q", got.Request.Path, "/v1/messages/dest-uuid")
	}
}

func TestMarshalUnmarshalFrame_Protobuf_Response(t *testing.T) {
	msg := &WebSocketMessage{
		Type: "response",
		Response: &WebSocketResponse{
			ID:      1,
			Status:  200,
			Message: "OK",
			Body:    base64.StdEncoding.EncodeToString([]byte(`{"needsSync":false}`)),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
	}

	data, err := MarshalFrame(msg, FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("MarshalFrame: %v", err)
	}

	got, err := UnmarshalFrame(data, FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("UnmarshalFrame: %v", err)
	}

	if got.Type != "response" {
		t.Errorf("Type = %q, want %q", got.Type, "response")
	}
	if got.Response.Status != 200 {
		t.Errorf("Status = %d, want %d", got.Response.Status, 200)
	}
	if got.Response.Message != "OK" {
		t.Errorf("Message = %q, want %q", got.Response.Message, "OK")
	}
}

func TestUnmarshalFrame_Protobuf_FromSignalClient(t *testing.T) {
	// Simulate a protobuf message as signal-cli would send it.
	pbMsg := &pb.WebSocketMessage{
		Type: pb.WebSocketMessage_REQUEST.Enum(),
		Request: &pb.WebSocketRequestMessage{
			Id:      proto.Uint64(5),
			Verb:    proto.String("PUT"),
			Path:    proto.String("/v1/messages/target-uuid"),
			Body:    []byte("raw-encrypted-bytes"),
			Headers: []string{"Content-Type: application/json"},
		},
	}

	data, err := proto.Marshal(pbMsg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	got, err := UnmarshalFrame(data, FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("UnmarshalFrame: %v", err)
	}

	if got.Type != "request" {
		t.Errorf("Type = %q, want %q", got.Type, "request")
	}
	if got.Request.ID != 5 {
		t.Errorf("ID = %d, want %d", got.Request.ID, 5)
	}
	if got.Request.Verb != "PUT" {
		t.Errorf("Verb = %q, want %q", got.Request.Verb, "PUT")
	}
	// Body should be base64-encoded.
	decoded, err := base64.StdEncoding.DecodeString(got.Request.Body)
	if err != nil {
		t.Fatalf("body is not valid base64: %v", err)
	}
	if string(decoded) != "raw-encrypted-bytes" {
		t.Errorf("body = %q, want %q", string(decoded), "raw-encrypted-bytes")
	}
	// Headers should be parsed into map.
	if got.Request.Headers["Content-Type"] != "application/json" {
		t.Errorf("Content-Type header = %q, want %q", got.Request.Headers["Content-Type"], "application/json")
	}
}

func TestMarshalFrame_Protobuf_EmptyBody(t *testing.T) {
	msg := &WebSocketMessage{
		Type: "request",
		Request: &WebSocketRequest{
			ID:   1,
			Verb: "GET",
			Path: "/api/v1/keepalive",
		},
	}

	data, err := MarshalFrame(msg, FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("MarshalFrame: %v", err)
	}

	got, err := UnmarshalFrame(data, FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("UnmarshalFrame: %v", err)
	}

	if got.Request.Body != "" {
		t.Errorf("Body = %q, want empty", got.Request.Body)
	}
}

func TestHeaderListToMap_Basic(t *testing.T) {
	headers := []string{
		"Content-Type: application/json",
		"Authorization: Basic dXNlcjpwYXNz",
	}

	m := headerListToMap(headers)

	if m["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q, want %q", m["Content-Type"], "application/json")
	}
	if m["Authorization"] != "Basic dXNlcjpwYXNz" {
		t.Errorf("Authorization = %q, want %q", m["Authorization"], "Basic dXNlcjpwYXNz")
	}
}

func TestHeaderListToMap_Empty(t *testing.T) {
	m := headerListToMap(nil)
	if m != nil {
		t.Errorf("expected nil map for nil input, got %v", m)
	}

	m = headerListToMap([]string{})
	if m != nil {
		t.Errorf("expected nil map for empty input, got %v", m)
	}
}

func TestMapToHeaderList_Basic(t *testing.T) {
	m := map[string]string{
		"Content-Type": "application/json",
	}

	headers := mapToHeaderList(m)
	if len(headers) != 1 {
		t.Fatalf("expected 1 header, got %d", len(headers))
	}
	if headers[0] != "Content-Type: application/json" {
		t.Errorf("header = %q, want %q", headers[0], "Content-Type: application/json")
	}
}

func TestMapToHeaderList_Empty(t *testing.T) {
	headers := mapToHeaderList(nil)
	if headers != nil {
		t.Errorf("expected nil for nil map, got %v", headers)
	}
}

func TestParseContentLength_Found(t *testing.T) {
	headers := []string{"Content-Type: application/json", "Content-Length: 42"}
	if n := parseContentLength(headers); n != 42 {
		t.Errorf("parseContentLength = %d, want 42", n)
	}
}

func TestParseContentLength_NotFound(t *testing.T) {
	headers := []string{"Content-Type: application/json"}
	if n := parseContentLength(headers); n != -1 {
		t.Errorf("parseContentLength = %d, want -1", n)
	}
}

func TestMarshalFrame_InvalidRequestBody_ReturnsFrameDecodeError(t *testing.T) {
	msg := &WebSocketMessage{
		Type: "request",
		Request: &WebSocketRequest{
			ID:   1,
			Verb: "PUT",
			Path: "/v1/messages/abc",
			Body: "!!!not-valid-base64!!!",
		},
	}

	_, err := MarshalFrame(msg, FrameFormatProtobuf)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var fde *FrameDecodeError
	if !errors.As(err, &fde) {
		t.Fatalf("expected *FrameDecodeError, got %T: %v", err, err)
	}
	if fde.Field != "request body" {
		t.Errorf("Field = %q, want %q", fde.Field, "request body")
	}
	if fde.Cause == nil {
		t.Error("Cause must not be nil")
	}
}

func TestMarshalFrame_InvalidResponseBody_ReturnsFrameDecodeError(t *testing.T) {
	msg := &WebSocketMessage{
		Type: "response",
		Response: &WebSocketResponse{
			ID:      2,
			Status:  200,
			Message: "OK",
			Body:    "!!!not-valid-base64!!!",
		},
	}

	_, err := MarshalFrame(msg, FrameFormatProtobuf)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var fde *FrameDecodeError
	if !errors.As(err, &fde) {
		t.Fatalf("expected *FrameDecodeError, got %T: %v", err, err)
	}
	if fde.Field != "response body" {
		t.Errorf("Field = %q, want %q", fde.Field, "response body")
	}
	if fde.Cause == nil {
		t.Error("Cause must not be nil")
	}
}

func TestFrameDecodeError_Error(t *testing.T) {
	tests := []struct {
		name    string
		err     *FrameDecodeError
		wantMsg string
	}{
		{
			name:    "field and cause",
			err:     &FrameDecodeError{Field: "request body", Cause: errors.New("illegal base64 data")},
			wantMsg: "frame decode error in request body: illegal base64 data",
		},
		{
			name:    "field only",
			err:     &FrameDecodeError{Field: "response body"},
			wantMsg: "frame decode error in response body",
		},
		{
			name:    "cause only",
			err:     &FrameDecodeError{Cause: errors.New("bad input")},
			wantMsg: "frame decode error: bad input",
		},
		{
			name:    "neither field nor cause",
			err:     &FrameDecodeError{},
			wantMsg: "frame decode error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.wantMsg {
				t.Errorf("Error() = %q, want %q", got, tc.wantMsg)
			}
		})
	}
}

func TestFrameDecodeError_Unwrap(t *testing.T) {
	sentinel := errors.New("root cause")

	t.Run("returns cause", func(t *testing.T) {
		fde := &FrameDecodeError{Field: "request body", Cause: sentinel}
		if !errors.Is(fde, sentinel) {
			t.Errorf("errors.Is did not find sentinel through Unwrap")
		}
	})

	t.Run("nil cause returns nil", func(t *testing.T) {
		fde := &FrameDecodeError{Field: "request body"}
		if fde.Unwrap() != nil {
			t.Errorf("Unwrap() = %v, want nil", fde.Unwrap())
		}
	})
}

func TestFrameFormat_UnknownType(t *testing.T) {
	msg := &WebSocketMessage{
		Type: "unknown",
	}

	data, err := MarshalFrame(msg, FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("MarshalFrame: %v", err)
	}

	got, err := UnmarshalFrame(data, FrameFormatProtobuf)
	if err != nil {
		t.Fatalf("UnmarshalFrame: %v", err)
	}

	if got.Type != "unknown" {
		t.Errorf("Type = %q, want %q", got.Type, "unknown")
	}
}
