package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/profiles"
)

// ProfileService defines the profile operations exposed to protocol handlers.
type ProfileService interface {
	// Set creates or replaces a versioned profile in the store.
	Set(ctx context.Context, profile *profiles.Profile) error

	// Get retrieves a specific version of a profile.
	Get(ctx context.Context, uuid string, version string) (*profiles.Profile, error)

	// GetLatest retrieves the most recently stored profile version.
	GetLatest(ctx context.Context, uuid string) (*profiles.Profile, error)

	// Delete removes all profile versions for a UUID.
	Delete(ctx context.Context, uuid string) error
}

// profileService is the default ProfileService backed by a ProfilesManager.
type profileService struct {
	manager *profiles.ProfilesManager
}

// NewProfileService returns a ProfileService that delegates to the given
// ProfilesManager. The manager must not be nil.
func NewProfileService(manager *profiles.ProfilesManager) ProfileService {
	return &profileService{manager: manager}
}

func (s *profileService) Set(ctx context.Context, profile *profiles.Profile) error {
	return s.manager.Set(ctx, profile)
}

func (s *profileService) Get(ctx context.Context, uuid string, version string) (*profiles.Profile, error) {
	return s.manager.Get(ctx, uuid, version)
}

func (s *profileService) GetLatest(ctx context.Context, uuid string) (*profiles.Profile, error) {
	return s.manager.GetLatest(ctx, uuid)
}

func (s *profileService) Delete(ctx context.Context, uuid string) error {
	return s.manager.Delete(ctx, uuid)
}
