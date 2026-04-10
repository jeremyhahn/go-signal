package profiles

import "context"

// ProfilesManager orchestrates profile operations through the underlying store.
type ProfilesManager struct {
	store ProfileStore
}

// NewProfilesManager creates a new ProfilesManager backed by the given store.
func NewProfilesManager(store ProfileStore) *ProfilesManager {
	return &ProfilesManager{store: store}
}

// Set creates or updates a profile version in the store.
func (m *ProfilesManager) Set(ctx context.Context, profile *Profile) error {
	return m.store.Set(ctx, profile)
}

// Get retrieves a specific version of a profile from the store.
func (m *ProfilesManager) Get(ctx context.Context, uuid string, version string) (*Profile, error) {
	return m.store.Get(ctx, uuid, version)
}

// GetLatest retrieves the most recently stored profile version from the store.
func (m *ProfilesManager) GetLatest(ctx context.Context, uuid string) (*Profile, error) {
	return m.store.GetLatest(ctx, uuid)
}

// Delete removes all profile versions for a UUID from the store.
func (m *ProfilesManager) Delete(ctx context.Context, uuid string) error {
	return m.store.Delete(ctx, uuid)
}
