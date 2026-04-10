package memory

import (
	"context"
	"sync"

	"github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
)

// Compile-time interface satisfaction check.
var _ profiles.ProfileStore = (*MemoryProfileStore)(nil)

// MemoryProfileStore implements profiles.ProfileStore with in-memory storage.
type MemoryProfileStore struct {
	mu sync.RWMutex
	// byUUID maps uuid -> version -> profile for versioned lookups.
	byUUID map[string]map[string]*profiles.Profile
	// latestVersion maps uuid -> most recently stored version string.
	latestVersion map[string]string
}

// NewMemoryProfileStore creates a new in-memory profile store.
func NewMemoryProfileStore() *MemoryProfileStore {
	return &MemoryProfileStore{
		byUUID:        make(map[string]map[string]*profiles.Profile),
		latestVersion: make(map[string]string),
	}
}

// Set creates or updates a profile version.
func (s *MemoryProfileStore) Set(_ context.Context, profile *profiles.Profile) error {
	stored := cloneProfile(profile)

	s.mu.Lock()
	defer s.mu.Unlock()

	versions, exists := s.byUUID[stored.UUID]
	if !exists {
		versions = make(map[string]*profiles.Profile)
		s.byUUID[stored.UUID] = versions
	}

	versions[stored.Version] = stored
	s.latestVersion[stored.UUID] = stored.Version

	return nil
}

// Get retrieves a specific version of a profile.
func (s *MemoryProfileStore) Get(_ context.Context, uuid string, version string) (*profiles.Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	versions, exists := s.byUUID[uuid]
	if !exists {
		return nil, errors.New(errors.ErrProfileNotFound, "profile not found: "+uuid)
	}

	profile, exists := versions[version]
	if !exists {
		return nil, errors.New(errors.ErrProfileNotFound, "profile version not found: "+uuid+"/"+version)
	}

	return cloneProfile(profile), nil
}

// GetLatest retrieves the most recently stored profile version.
func (s *MemoryProfileStore) GetLatest(_ context.Context, uuid string) (*profiles.Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	version, exists := s.latestVersion[uuid]
	if !exists {
		return nil, errors.New(errors.ErrProfileNotFound, "profile not found: "+uuid)
	}

	versions := s.byUUID[uuid]
	profile, exists := versions[version]
	if !exists {
		return nil, errors.New(errors.ErrProfileNotFound, "profile version not found: "+uuid+"/"+version)
	}

	return cloneProfile(profile), nil
}

// Delete removes all profile versions for a UUID.
func (s *MemoryProfileStore) Delete(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byUUID[uuid]; !exists {
		return errors.New(errors.ErrProfileNotFound, "profile not found: "+uuid)
	}

	delete(s.byUUID, uuid)
	delete(s.latestVersion, uuid)

	return nil
}

// cloneProfile returns a deep copy of a profile.
func cloneProfile(p *profiles.Profile) *profiles.Profile {
	return &profiles.Profile{
		UUID:           p.UUID,
		Version:        p.Version,
		Name:           cloneBytes(p.Name),
		About:          cloneBytes(p.About),
		AboutEmoji:     cloneBytes(p.AboutEmoji),
		Avatar:         p.Avatar,
		Commitment:     cloneBytes(p.Commitment),
		PaymentAddress: cloneBytes(p.PaymentAddress),
	}
}
