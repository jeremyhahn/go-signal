package keytransparency

import (
	"testing"
)

func TestSearchRequest_ZeroValue(t *testing.T) {
	var req SearchRequest
	if req.Token != nil {
		t.Errorf("expected nil token, got %v", req.Token)
	}
}

func TestSearchRequest_Fields(t *testing.T) {
	req := SearchRequest{Token: []byte{0x01, 0x02}}
	if len(req.Token) != 2 {
		t.Errorf("got %d bytes, want 2", len(req.Token))
	}
}

func TestSearchResponse_ZeroValue(t *testing.T) {
	var resp SearchResponse
	if resp.Token != nil {
		t.Errorf("expected nil token, got %v", resp.Token)
	}
}

func TestSearchResponse_Fields(t *testing.T) {
	resp := SearchResponse{Token: []byte{0xAB, 0xCD}}
	if len(resp.Token) != 2 {
		t.Errorf("got %d bytes, want 2", len(resp.Token))
	}
}

func TestMonitorRequest_ZeroValue(t *testing.T) {
	var req MonitorRequest
	if req.Token != nil {
		t.Errorf("expected nil token, got %v", req.Token)
	}
}

func TestMonitorRequest_Fields(t *testing.T) {
	req := MonitorRequest{Token: []byte("monitor")}
	if string(req.Token) != "monitor" {
		t.Errorf("got %q, want %q", string(req.Token), "monitor")
	}
}

func TestMonitorResponse_ZeroValue(t *testing.T) {
	var resp MonitorResponse
	if resp.Token != nil {
		t.Errorf("expected nil token, got %v", resp.Token)
	}
}

func TestMonitorResponse_Fields(t *testing.T) {
	resp := MonitorResponse{Token: []byte{0xFF}}
	if len(resp.Token) != 1 {
		t.Errorf("got %d bytes, want 1", len(resp.Token))
	}
}

func TestDistinguishedKeyResponse_ZeroValue(t *testing.T) {
	var resp DistinguishedKeyResponse
	if resp.Key != nil {
		t.Errorf("expected nil key, got %v", resp.Key)
	}
}

func TestDistinguishedKeyResponse_Fields(t *testing.T) {
	resp := DistinguishedKeyResponse{Key: []byte("pubkey-data")}
	if string(resp.Key) != "pubkey-data" {
		t.Errorf("got %q, want %q", string(resp.Key), "pubkey-data")
	}
}
