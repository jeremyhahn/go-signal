package websocket

import (
	"encoding/base64"
	"encoding/json"
	"strconv"

	"google.golang.org/protobuf/proto"

	pb "github.com/jeremyhahn/go-signal/pkg/websocket/wsproto"
)

// FrameFormat identifies the serialization format of WebSocket frames.
type FrameFormat int

const (
	// FrameFormatJSON uses JSON text frames (Go test clients).
	FrameFormatJSON FrameFormat = iota
	// FrameFormatProtobuf uses binary protobuf frames (signal-cli / Signal apps).
	FrameFormatProtobuf
)

// MarshalFrame serializes a WebSocketMessage into the given format.
func MarshalFrame(msg *WebSocketMessage, format FrameFormat) ([]byte, error) {
	switch format {
	case FrameFormatProtobuf:
		return marshalProtobuf(msg)
	default:
		return json.Marshal(msg)
	}
}

// UnmarshalFrame deserializes a WebSocketMessage from the given format.
func UnmarshalFrame(data []byte, format FrameFormat) (*WebSocketMessage, error) {
	switch format {
	case FrameFormatProtobuf:
		return unmarshalProtobuf(data)
	default:
		var msg WebSocketMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			return nil, err
		}
		return &msg, nil
	}
}

// marshalProtobuf converts a WebSocketMessage to its protobuf wire format.
func marshalProtobuf(msg *WebSocketMessage) ([]byte, error) {
	pbMsg := &pb.WebSocketMessage{}

	switch msg.Type {
	case "request":
		pbMsg.Type = pb.WebSocketMessage_REQUEST.Enum()
	case "response":
		pbMsg.Type = pb.WebSocketMessage_RESPONSE.Enum()
	default:
		pbMsg.Type = pb.WebSocketMessage_UNKNOWN.Enum()
	}

	if msg.Request != nil {
		pbReq := &pb.WebSocketRequestMessage{
			Id:   proto.Uint64(msg.Request.ID),
			Verb: proto.String(msg.Request.Verb),
			Path: proto.String(msg.Request.Path),
		}
		if msg.Request.Body != "" {
			body, err := base64.StdEncoding.DecodeString(msg.Request.Body)
			if err != nil {
				return nil, &FrameDecodeError{Field: "request body", Cause: err}
			}
			pbReq.Body = body
		}
		pbReq.Headers = mapToHeaderList(msg.Request.Headers)
		pbMsg.Request = pbReq
	}

	if msg.Response != nil {
		pbResp := &pb.WebSocketResponseMessage{
			Id:      proto.Uint64(msg.Response.ID),
			Status:  proto.Uint32(uint32(msg.Response.Status)),
			Message: proto.String(msg.Response.Message),
		}
		if msg.Response.Body != "" {
			body, err := base64.StdEncoding.DecodeString(msg.Response.Body)
			if err != nil {
				return nil, &FrameDecodeError{Field: "response body", Cause: err}
			}
			pbResp.Body = body
		}
		pbResp.Headers = mapToHeaderList(msg.Response.Headers)
		pbMsg.Response = pbResp
	}

	return proto.Marshal(pbMsg)
}

// unmarshalProtobuf converts protobuf wire format to a WebSocketMessage.
func unmarshalProtobuf(data []byte) (*WebSocketMessage, error) {
	pbMsg := &pb.WebSocketMessage{}
	if err := proto.Unmarshal(data, pbMsg); err != nil {
		return nil, err
	}

	msg := &WebSocketMessage{}
	switch pbMsg.GetType() {
	case pb.WebSocketMessage_REQUEST:
		msg.Type = "request"
	case pb.WebSocketMessage_RESPONSE:
		msg.Type = "response"
	default:
		msg.Type = "unknown"
	}

	if pbMsg.Request != nil {
		req := &WebSocketRequest{
			ID:   pbMsg.Request.GetId(),
			Verb: pbMsg.Request.GetVerb(),
			Path: pbMsg.Request.GetPath(),
		}
		if len(pbMsg.Request.Body) > 0 {
			req.Body = base64.StdEncoding.EncodeToString(pbMsg.Request.Body)
		}
		req.Headers = headerListToMap(pbMsg.Request.Headers)
		msg.Request = req
	}

	if pbMsg.Response != nil {
		resp := &WebSocketResponse{
			ID:      pbMsg.Response.GetId(),
			Status:  int(pbMsg.Response.GetStatus()),
			Message: pbMsg.Response.GetMessage(),
		}
		if len(pbMsg.Response.Body) > 0 {
			resp.Body = base64.StdEncoding.EncodeToString(pbMsg.Response.Body)
		}
		resp.Headers = headerListToMap(pbMsg.Response.Headers)
		msg.Response = resp
	}

	return msg, nil
}

// mapToHeaderList converts a map[string]string to a list of "Key: Value" strings
// matching the protobuf repeated string headers format.
func mapToHeaderList(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	headers := make([]string, 0, len(m))
	for k, v := range m {
		headers = append(headers, k+": "+v)
	}
	return headers
}

// headerListToMap converts a list of "Key: Value" strings to a map.
func headerListToMap(headers []string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	m := make(map[string]string, len(headers))
	for _, h := range headers {
		for i := 0; i < len(h); i++ {
			if h[i] == ':' {
				key := h[:i]
				val := h[i+1:]
				if len(val) > 0 && val[0] == ' ' {
					val = val[1:]
				}
				m[key] = val
				break
			}
		}
	}
	return m
}

// parseContentLength extracts the Content-Length header value from the protobuf
// headers list. Returns -1 if not found or unparseable.
func parseContentLength(headers []string) int64 {
	for _, h := range headers {
		for i := 0; i < len(h); i++ {
			if h[i] == ':' {
				key := h[:i]
				if key == "Content-Length" || key == "content-length" {
					val := h[i+1:]
					if len(val) > 0 && val[0] == ' ' {
						val = val[1:]
					}
					n, err := strconv.ParseInt(val, 10, 64)
					if err == nil {
						return n
					}
				}
				break
			}
		}
	}
	return -1
}
