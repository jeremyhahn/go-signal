package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/registration/recoverypassword"
)

// RecoveryPasswordService defines the registration recovery password
// operations exposed to protocol handlers.
type RecoveryPasswordService interface {
	// Verify returns true if password matches the recovery password currently
	// associated with pni. Returns false (with a nil error) when no entry
	// exists, the entry has expired, or the password does not verify.
	Verify(ctx context.Context, pni string, password []byte) (bool, error)

	// Store inserts or replaces the recovery password for pni. The supplied
	// bytes are hashed with a fresh random salt before persisting.
	Store(ctx context.Context, pni string, password []byte) error
}

// recoveryPasswordService is the default RecoveryPasswordService backed by a
// recoverypassword.Manager.
type recoveryPasswordService struct {
	manager *recoverypassword.Manager
}

// NewRecoveryPasswordService returns a RecoveryPasswordService that delegates
// to the given Manager. The manager must not be nil.
func NewRecoveryPasswordService(manager *recoverypassword.Manager) RecoveryPasswordService {
	return &recoveryPasswordService{manager: manager}
}

func (s *recoveryPasswordService) Verify(ctx context.Context, pni string, password []byte) (bool, error) {
	return s.manager.Verify(ctx, pni, password)
}

func (s *recoveryPasswordService) Store(ctx context.Context, pni string, password []byte) error {
	return s.manager.Store(ctx, pni, password)
}

// Compile-time assertion: recoverypassword.Manager must satisfy RecoveryPasswordService.
var _ RecoveryPasswordService = (*recoverypassword.Manager)(nil)
