package websocket

import (
	"encoding/base64"
	"encoding/json"
)

// mustMarshalBase64 serializes v as JSON and base64-encodes the result. If
// marshaling fails, an empty string is returned.
func mustMarshalBase64(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
}

// encodeBase64 base64-encodes raw bytes.
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
