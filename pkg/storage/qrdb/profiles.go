package qrdb

import (
	"context"
	"encoding/json"
	"errors"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
)

// Profiles are versioned per account. Layout:
//
//	profile:{uuid}:{version} → JSON profile
//	profile:{uuid}:_latest   → JSON profile (mirror of the most recent Set).
//
// GetLatest reads the _latest mirror; Get by version reads the primary.
// Scanning "profile:{uuid}:" returns both primary and mirror records, so
// list operations that want only primaries must filter out the _latest tail.

const profileKeyPrefix = "profile:"

var _ profiles.ProfileStore = (*ProfileStore)(nil)

// ProfileStore is a qrdb-backed implementation of profiles.ProfileStore.
type ProfileStore struct {
	kv KVStore
}

// NewProfileStore returns a ProfileStore that persists to kv.
func NewProfileStore(kv KVStore) *ProfileStore { return &ProfileStore{kv: kv} }

func profileKey(uuid, version string) string {
	return profileKeyPrefix + uuid + ":" + version
}
func profileLatestKey(uuid string) string { return profileKeyPrefix + uuid + ":_latest" }
func profileAllPrefix(uuid string) string { return profileKeyPrefix + uuid + ":" }

// Set stores a profile version. Replaces any existing profile at the same
// (uuid, version) pair and also updates the latest-version mirror.
func (s *ProfileStore) Set(ctx context.Context, profile *profiles.Profile) error {
	if profile == nil {
		return &profiles.InvalidArgumentError{Field: "profile", Message: "nil profile"}
	}
	if profile.UUID == "" {
		return &profiles.InvalidArgumentError{Field: "uuid", Message: "empty UUID"}
	}
	if profile.Version == "" {
		return &profiles.InvalidArgumentError{Field: "version", Message: "empty version"}
	}

	data, err := json.Marshal(profile)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb profiles: marshal", err)
	}
	if err := s.kv.Put(ctx, profileKey(profile.UUID, profile.Version), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb profiles: put", err)
	}
	if err := s.kv.Put(ctx, profileLatestKey(profile.UUID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb profiles: put latest", err)
	}
	return nil
}

// Get retrieves a specific version of a profile.
func (s *ProfileStore) Get(ctx context.Context, uuid, version string) (*profiles.Profile, error) {
	data, err := getOrNotFound(ctx, s.kv, profileKey(uuid, version))
	if errors.Is(err, ErrNotFound) {
		return nil, &profiles.ProfileNotFoundError{UUID: uuid, Version: version}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb profiles: get", err)
	}
	var p profiles.Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb profiles: unmarshal", err)
	}
	return &p, nil
}

// GetLatest returns the most recently written profile for an account.
func (s *ProfileStore) GetLatest(ctx context.Context, uuid string) (*profiles.Profile, error) {
	data, err := getOrNotFound(ctx, s.kv, profileLatestKey(uuid))
	if errors.Is(err, ErrNotFound) {
		return nil, &profiles.ProfileNotFoundError{UUID: uuid}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb profiles: get latest", err)
	}
	var p profiles.Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb profiles: unmarshal", err)
	}
	return &p, nil
}

// Delete removes every version of a UUID's profiles, including the latest
// mirror.
func (s *ProfileStore) Delete(ctx context.Context, uuid string) error {
	keys, err := s.kv.List(ctx, profileAllPrefix(uuid))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb profiles: list", err)
	}
	for _, k := range keys {
		if err := s.kv.Delete(ctx, k); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb profiles: delete "+k, err)
		}
	}
	return nil
}
