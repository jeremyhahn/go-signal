package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/keytransparency"
)

// KeyTransparencyService defines the key transparency operations exposed to
// protocol handlers.
type KeyTransparencyService interface {
	// Search proxies a key transparency search request to the remote
	// service, or returns a stub response when no remote is configured.
	Search(ctx context.Context, req *keytransparency.SearchRequest) (*keytransparency.SearchResponse, error)

	// Monitor proxies a key transparency monitor request to the remote
	// service, or returns a stub response when no remote is configured.
	Monitor(ctx context.Context, req *keytransparency.MonitorRequest) (*keytransparency.MonitorResponse, error)

	// GetDistinguishedKey returns the distinguished tree key from the remote
	// service, or an empty stub when no remote is configured.
	GetDistinguishedKey(ctx context.Context) (*keytransparency.DistinguishedKeyResponse, error)
}

// keyTransparencyService is the default KeyTransparencyService backed by a
// KeyTransparencyManager.
type keyTransparencyService struct {
	manager *keytransparency.KeyTransparencyManager
}

// NewKeyTransparencyService returns a KeyTransparencyService that delegates
// to the given KeyTransparencyManager. The manager must not be nil.
func NewKeyTransparencyService(manager *keytransparency.KeyTransparencyManager) KeyTransparencyService {
	return &keyTransparencyService{manager: manager}
}

func (s *keyTransparencyService) Search(ctx context.Context, req *keytransparency.SearchRequest) (*keytransparency.SearchResponse, error) {
	return s.manager.Search(ctx, req)
}

func (s *keyTransparencyService) Monitor(ctx context.Context, req *keytransparency.MonitorRequest) (*keytransparency.MonitorResponse, error) {
	return s.manager.Monitor(ctx, req)
}

func (s *keyTransparencyService) GetDistinguishedKey(ctx context.Context) (*keytransparency.DistinguishedKeyResponse, error) {
	return s.manager.GetDistinguishedKey(ctx)
}

// Compile-time assertion: KeyTransparencyManager must satisfy KeyTransparencyService.
var _ KeyTransparencyService = (*keytransparency.KeyTransparencyManager)(nil)
