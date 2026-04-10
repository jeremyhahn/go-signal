// Package websocket provides WebSocket session management and real-time message
// delivery for the Signal server. It implements the Signal WebSocket protocol's
// request/response multiplexing scheme over JSON-encoded frames.
package websocket

// WebSocketMessage is the top-level frame sent over the WebSocket connection.
// Each frame carries either a request or a response, identified by the Type
// field.
type WebSocketMessage struct {
	Type     string             `json:"type"` // "request" or "response"
	Request  *WebSocketRequest  `json:"request,omitempty"`
	Response *WebSocketResponse `json:"response,omitempty"`
}

// WebSocketRequest is a request from client to server or server to client.
// Requests use HTTP-like verb/path routing and carry an ID for correlating
// responses.
type WebSocketRequest struct {
	ID      uint64            `json:"id"`
	Verb    string            `json:"verb"`
	Path    string            `json:"path"`
	Body    string            `json:"body,omitempty"` // base64 encoded
	Headers map[string]string `json:"headers,omitempty"`
}

// WebSocketResponse is a response to a WebSocketRequest. The ID field
// correlates the response back to the original request.
type WebSocketResponse struct {
	ID      uint64            `json:"id"`
	Status  int               `json:"status"`
	Message string            `json:"message,omitempty"`
	Body    string            `json:"body,omitempty"` // base64 encoded
	Headers map[string]string `json:"headers,omitempty"`
}
