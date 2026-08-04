package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/directory"
)

// DirectoryService defines the contact discovery credential operations
// exposed to protocol handlers.
type DirectoryService interface {
	// GetAuthToken returns CDSI credentials for the given account UUID.
	GetAuthToken(ctx context.Context, accountUUID string) (*directory.DirectoryCredentials, error)
}

// directoryService is the default DirectoryService backed by a DirectoryManager.
type directoryService struct {
	manager *directory.DirectoryManager
}

// NewDirectoryService returns a DirectoryService that delegates to the given
// DirectoryManager. The manager must not be nil.
func NewDirectoryService(manager *directory.DirectoryManager) DirectoryService {
	return &directoryService{manager: manager}
}

func (s *directoryService) GetAuthToken(ctx context.Context, accountUUID string) (*directory.DirectoryCredentials, error) {
	return s.manager.GetAuthToken(ctx, accountUUID)
}

// Compile-time assertion: DirectoryManager must satisfy DirectoryService.
var _ DirectoryService = (*directory.DirectoryManager)(nil)
