package profiles

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

const (
	kvProfilePrefix = "signal/profiles/"
	kvLatestSuffix  = "/_latest"
)

// KVProfileStore implements ProfileStore using a KVClient backend.
type KVProfileStore struct {
	kv store.KVClient
}

// NewKVProfileStore returns a new KVProfileStore backed by the given KVClient.
func NewKVProfileStore(kv store.KVClient) *KVProfileStore {
	return &KVProfileStore{kv: kv}
}

// Set creates or updates a profile version and updates the latest marker.
func (s *KVProfileStore) Set(ctx context.Context, profile *Profile) error {
	key := kvProfilePrefix + profile.UUID + "/" + profile.Version
	data, err := json.Marshal(profile)
	if err != nil {
		return &InvalidArgumentError{Field: "profile", Message: "failed to marshal: " + err.Error()}
	}

	if err := s.kv.Put(ctx, key, data); err != nil {
		return err
	}

	latestKey := kvProfilePrefix + profile.UUID + kvLatestSuffix
	return s.kv.Put(ctx, latestKey, []byte(profile.Version))
}

// Get retrieves a specific version of a profile.
func (s *KVProfileStore) Get(ctx context.Context, uuid string, version string) (*Profile, error) {
	key := kvProfilePrefix + uuid + "/" + version
	data, err := s.kv.Get(ctx, key)
	if err != nil {
		var knf *store.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, &ProfileNotFoundError{UUID: uuid, Version: version}
		}
		return nil, err
	}

	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, &InvalidArgumentError{Field: "profile", Message: "failed to unmarshal: " + err.Error()}
	}
	return &profile, nil
}

// GetLatest retrieves the most recently stored profile version.
func (s *KVProfileStore) GetLatest(ctx context.Context, uuid string) (*Profile, error) {
	latestKey := kvProfilePrefix + uuid + kvLatestSuffix
	versionData, err := s.kv.Get(ctx, latestKey)
	if err != nil {
		var knf *store.KeyNotFoundError
		if errors.As(err, &knf) {
			return nil, &ProfileNotFoundError{UUID: uuid}
		}
		return nil, err
	}

	return s.Get(ctx, uuid, string(versionData))
}

// Delete removes all profile versions and the latest marker for a UUID.
func (s *KVProfileStore) Delete(ctx context.Context, uuid string) error {
	prefix := kvProfilePrefix + uuid + "/"
	keys, err := s.kv.List(ctx, prefix)
	if err != nil {
		return err
	}

	// Also include the latest marker.
	latestKey := kvProfilePrefix + uuid + kvLatestSuffix

	hasLatest, err := s.kv.Exists(ctx, latestKey)
	if err != nil {
		return err
	}

	if len(keys) == 0 && !hasLatest {
		return &ProfileNotFoundError{UUID: uuid}
	}

	for _, k := range keys {
		if err := s.kv.Delete(ctx, k); err != nil {
			var knf *store.KeyNotFoundError
			if errors.As(err, &knf) {
				continue
			}
			return err
		}
	}

	if hasLatest {
		if err := s.kv.Delete(ctx, latestKey); err != nil {
			var knf *store.KeyNotFoundError
			if !errors.As(err, &knf) {
				return err
			}
		}
	}

	return nil
}
