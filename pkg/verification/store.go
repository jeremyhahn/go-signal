package verification

import "context"

// VerificationSessionStore persists verification sessions.
type VerificationSessionStore interface {
	// Create stores a new verification session.
	Create(ctx context.Context, session *VerificationSession) error

	// Get retrieves a verification session by ID.
	Get(ctx context.Context, sessionID string) (*VerificationSession, error)

	// Update replaces an existing verification session.
	Update(ctx context.Context, session *VerificationSession) error

	// Delete removes a verification session by ID.
	Delete(ctx context.Context, sessionID string) error

	// Count returns the number of sessions currently in the store.
	Count(ctx context.Context) (int, error)

	// DeleteExpired removes all sessions whose ExpiresAt is in the past.
	// It is called by the Manager's background cleanup goroutine.
	DeleteExpired(ctx context.Context) error
}
