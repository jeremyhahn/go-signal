package profiles

import "context"

// ProfileStore defines the storage interface for Signal user profiles.
type ProfileStore interface {
	// Set creates or updates a profile version.
	Set(ctx context.Context, profile *Profile) error

	// Get retrieves a specific version of a profile.
	Get(ctx context.Context, uuid string, version string) (*Profile, error)

	// GetLatest retrieves the most recently stored profile version.
	GetLatest(ctx context.Context, uuid string) (*Profile, error)

	// Delete removes all profile versions for a UUID.
	Delete(ctx context.Context, uuid string) error
}
