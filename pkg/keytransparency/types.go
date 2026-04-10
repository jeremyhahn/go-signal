package keytransparency

// SearchRequest is the JSON body for a key transparency search operation.
type SearchRequest struct {
	Token []byte `json:"token"`
}

// SearchResponse is the result of a key transparency search.
type SearchResponse struct {
	Token []byte `json:"token"`
}

// MonitorRequest is the JSON body for a key transparency monitor operation.
type MonitorRequest struct {
	Token []byte `json:"token"`
}

// MonitorResponse is the result of a key transparency monitor operation.
type MonitorResponse struct {
	Token []byte `json:"token"`
}

// DistinguishedKeyResponse contains the distinguished tree key.
type DistinguishedKeyResponse struct {
	Key []byte `json:"key"`
}
