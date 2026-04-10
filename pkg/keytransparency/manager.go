package keytransparency

import (
	"context"
	"log/slog"
)

// KeyTransparencyManager manages key transparency auditing operations.
type KeyTransparencyManager struct {
	logger *slog.Logger
}

// NewKeyTransparencyManager creates a new KeyTransparencyManager.
func NewKeyTransparencyManager(logger *slog.Logger) *KeyTransparencyManager {
	return &KeyTransparencyManager{logger: logger}
}

// Search performs a stub key transparency search returning a minimal response.
func (m *KeyTransparencyManager) Search(ctx context.Context, req *SearchRequest) (*SearchResponse, error) {
	return &SearchResponse{Token: []byte{}}, nil
}

// Monitor performs a stub key transparency monitor returning a minimal
// response.
func (m *KeyTransparencyManager) Monitor(ctx context.Context, req *MonitorRequest) (*MonitorResponse, error) {
	return &MonitorResponse{Token: []byte{}}, nil
}

// GetDistinguishedKey returns a stub distinguished key response.
func (m *KeyTransparencyManager) GetDistinguishedKey(ctx context.Context) (*DistinguishedKeyResponse, error) {
	return &DistinguishedKeyResponse{Key: []byte{}}, nil
}
