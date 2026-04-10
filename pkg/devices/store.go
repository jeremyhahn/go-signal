package devices

import "context"

// ProvisioningStore defines the storage interface for device provisioning
// sessions.
type ProvisioningStore interface {
	// StoreSession persists a new provisioning session.
	StoreSession(ctx context.Context, session *ProvisioningSession) error

	// GetSession retrieves a provisioning session by its verification code.
	GetSession(ctx context.Context, code string) (*ProvisioningSession, error)

	// DeleteSession removes a provisioning session by its verification code.
	DeleteSession(ctx context.Context, code string) error
}
