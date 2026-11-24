package qrdb

import (
	"context"
	"encoding/json"
	"sort"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/remoteconfig"
)

// remoteConfigKeyPrefix namespaces all dynamic-config rows. Keys are
// `remoteconfig:<name>`; a Scan against the prefix yields the full
// row set in lexicographic order.
const remoteConfigKeyPrefix = "remoteconfig:"

// RemoteConfigStore is a KVStore-backed implementation of
// remoteconfig.Store. Used by the "file" storage backend in
// cmd/signald so file-mode deployments can persist live config edits
// across restarts.
type RemoteConfigStore struct {
	kv KVStore
}

// Compile-time interface satisfaction check.
var _ remoteconfig.Store = (*RemoteConfigStore)(nil)

// NewRemoteConfigStore returns a store backed by kv.
func NewRemoteConfigStore(kv KVStore) *RemoteConfigStore {
	return &RemoteConfigStore{kv: kv}
}

// remoteConfigRow is the serialized wire shape. Mirrors
// remoteconfig.Config except UUIDs becomes a slice for stable
// JSON encoding.
type remoteConfigRow struct {
	Name         string   `json:"name"`
	Percentage   int      `json:"percentage"`
	UUIDs        []string `json:"uuids,omitempty"`
	Value        string   `json:"value,omitempty"`
	DefaultValue string   `json:"defaultValue,omitempty"`
	HashKey      string   `json:"hashKey,omitempty"`
}

func rowFromConfig(c remoteconfig.Config) remoteConfigRow {
	row := remoteConfigRow{
		Name:         c.Name,
		Percentage:   c.Percentage,
		Value:        c.Value,
		DefaultValue: c.DefaultValue,
		HashKey:      c.HashKey,
	}
	if len(c.UUIDs) > 0 {
		row.UUIDs = make([]string, 0, len(c.UUIDs))
		for u := range c.UUIDs {
			row.UUIDs = append(row.UUIDs, u)
		}
		sort.Strings(row.UUIDs)
	}
	return row
}

func configFromRow(r remoteConfigRow) remoteconfig.Config {
	c := remoteconfig.Config{
		Name:         r.Name,
		Percentage:   r.Percentage,
		Value:        r.Value,
		DefaultValue: r.DefaultValue,
		HashKey:      r.HashKey,
	}
	if len(r.UUIDs) > 0 {
		c.UUIDs = make(map[string]struct{}, len(r.UUIDs))
		for _, u := range r.UUIDs {
			c.UUIDs[u] = struct{}{}
		}
	}
	return c
}

// GetAll returns every row sorted by name.
func (s *RemoteConfigStore) GetAll(ctx context.Context) ([]remoteconfig.Config, error) {
	var rows []remoteconfig.Config
	err := s.kv.Scan(ctx, remoteConfigKeyPrefix, func(_ string, value []byte) error {
		var r remoteConfigRow
		if err := json.Unmarshal(value, &r); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb: remote_config decode", err)
		}
		rows = append(rows, configFromRow(r))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

// Put writes the row, replacing any existing entry with the same name.
func (s *RemoteConfigStore) Put(ctx context.Context, cfg remoteconfig.Config) error {
	if cfg.Name == "" {
		return &remoteconfig.InvalidConfigError{Reason: "Name is required"}
	}
	if cfg.Percentage < 0 || cfg.Percentage > 100 {
		return &remoteconfig.InvalidConfigError{Reason: "Percentage must be in [0,100]"}
	}
	row := rowFromConfig(cfg)
	value, err := json.Marshal(row)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb: remote_config encode", err)
	}
	return s.kv.Put(ctx, remoteConfigKeyPrefix+cfg.Name, value)
}

// Delete removes a row by name. Idempotent.
func (s *RemoteConfigStore) Delete(ctx context.Context, name string) error {
	if name == "" {
		return nil
	}
	return s.kv.Delete(ctx, remoteConfigKeyPrefix+name)
}
