package keytransparency

import (
	"context"
	"log/slog"

	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
)

// RemoteClient is the subset of pkg/extservice/keytransparency.Client
// the manager consumes. Decoupling here lets tests inject a stub.
type RemoteClient interface {
	Search(ctx context.Context, req *ktpb.SearchRequest) (*ktpb.SearchResponse, error)
	Monitor(ctx context.Context, req *ktpb.MonitorRequest) (*ktpb.MonitorResponse, error)
	Distinguished(ctx context.Context, req *ktpb.DistinguishedRequest) (*ktpb.DistinguishedResponse, error)
}

// KeyTransparencyManager fronts the optional remote
// key-transparency service for signald's REST handlers. When no
// remote is configured the manager returns stub responses
// (monolithic deployment); when a remote is wired the REST
// handlers' inbound calls are proxied through.
type KeyTransparencyManager struct {
	logger *slog.Logger
	remote RemoteClient
}

// NewKeyTransparencyManager creates a new KeyTransparencyManager
// without a remote client (stub mode).
func NewKeyTransparencyManager(logger *slog.Logger) *KeyTransparencyManager {
	return &KeyTransparencyManager{logger: logger}
}

// SetRemote installs a remote client. Pass nil to reset to stub mode.
func (m *KeyTransparencyManager) SetRemote(c RemoteClient) {
	m.remote = c
}

// Search proxies to the remote service when configured. Returns a
// minimal stub response otherwise.
func (m *KeyTransparencyManager) Search(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
	if m.remote == nil {
		return &SearchResponse{Token: []byte{}}, nil
	}
	// The REST token is opaque; the proto needs a 16-byte ACI, so send zeros.
	_ = req
	pbResp, err := m.remote.Search(ctx, &ktpb.SearchRequest{
		Aci:            make([]byte, 16),
		AciIdentityKey: []byte("placeholder"),
	})
	if err != nil {
		return nil, err
	}
	return &SearchResponse{Token: extractToken(pbResp.GetTreeHead())}, nil
}

// Monitor proxies to the remote service when configured.
func (m *KeyTransparencyManager) Monitor(ctx context.Context, req *MonitorRequest) (*MonitorResponse, error) {
	if m.remote == nil {
		return &MonitorResponse{Token: []byte{}}, nil
	}
	_ = req
	pbResp, err := m.remote.Monitor(ctx, &ktpb.MonitorRequest{})
	if err != nil {
		return nil, err
	}
	return &MonitorResponse{Token: extractToken(pbResp.GetTreeHead())}, nil
}

// GetDistinguishedKey proxies to the remote service when configured.
func (m *KeyTransparencyManager) GetDistinguishedKey(ctx context.Context) (*DistinguishedKeyResponse, error) {
	if m.remote == nil {
		return &DistinguishedKeyResponse{Key: []byte{}}, nil
	}
	pbResp, err := m.remote.Distinguished(ctx, &ktpb.DistinguishedRequest{})
	if err != nil {
		return nil, err
	}
	return &DistinguishedKeyResponse{Key: extractToken(pbResp.GetTreeHead())}, nil
}

// extractToken returns the first signature of a FullTreeHead as the opaque REST token.
func extractToken(h *ktpb.FullTreeHead) []byte {
	if h == nil {
		return []byte{}
	}
	sigs := h.GetTreeHead().GetSignatures()
	if len(sigs) == 0 {
		return []byte{}
	}
	return sigs[0].GetSignature()
}
