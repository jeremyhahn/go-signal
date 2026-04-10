package directory

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

// DirectoryManager manages contact discovery operations.
type DirectoryManager struct {
	logger *slog.Logger
}

// NewDirectoryManager creates a new DirectoryManager.
func NewDirectoryManager(logger *slog.Logger) *DirectoryManager {
	return &DirectoryManager{logger: logger}
}

// GetAuthToken returns stub credentials for the contact discovery service.
func (m *DirectoryManager) GetAuthToken(ctx context.Context, accountUUID string) (*DirectoryCredentials, error) {
	return &DirectoryCredentials{
		Username: accountUUID,
		Password: uuid.NewString(),
	}, nil
}
