package securevaluerecovery

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// SVRManager manages secure value recovery operations.
type SVRManager struct {
	logger *slog.Logger
}

// NewSVRManager creates a new SVRManager.
func NewSVRManager(logger *slog.Logger) *SVRManager {
	return &SVRManager{logger: logger}
}

// GetAuth returns stub credentials for the given SVR service name (backup or
// svr).
func (m *SVRManager) GetAuth(ctx context.Context, accountUUID, name string) (*SVRCredentials, error) {
	password, err := secrets.NewSecureString(ctx, uuid.NewString())
	if err != nil {
		return nil, err
	}
	return &SVRCredentials{
		Username: accountUUID,
		Password: password,
	}, nil
}

// CheckAuth validates the given passwords against the SVR service. This stub
// implementation marks all passwords as "no-match".
func (m *SVRManager) CheckAuth(ctx context.Context, accountUUID, name string, passwords []string) (*AuthCheckResponse, error) {
	matches := make(map[string]string, len(passwords))
	for _, pw := range passwords {
		matches[pw] = "no-match"
	}
	return &AuthCheckResponse{Matches: matches}, nil
}
