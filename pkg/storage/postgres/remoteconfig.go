package postgres

import (
	"context"
	"encoding/json"
	"strconv"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/remoteconfig"
)

// RemoteConfigStore persists feature-flag rows to the
// `remote_config` table. Implements remoteconfig.Store. The
// dynamic-config manager polls GetAll on its refresh interval; the
// admin REST surface drives Put/Delete.
type RemoteConfigStore struct {
	q Querier
}

// Compile-time interface satisfaction check.
var _ remoteconfig.Store = (*RemoteConfigStore)(nil)

// NewRemoteConfigStore returns a store backed by c.
func NewRemoteConfigStore(c *Client) *RemoteConfigStore {
	return &RemoteConfigStore{q: c.Pool()}
}

// GetAll returns every row sorted by name. The result is deterministic
// so the manager's diff-against-cache compares cleanly.
func (s *RemoteConfigStore) GetAll(ctx context.Context) ([]remoteconfig.Config, error) {
	const stmt = `
		SELECT name, percentage, uuids, value, default_value, hash_key
		  FROM remote_config
		 ORDER BY name`
	rows, err := s.q.Query(ctx, stmt)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres: remote_config query", err)
	}
	defer rows.Close()

	var out []remoteconfig.Config
	for rows.Next() {
		var c remoteconfig.Config
		var uuidsJSON []byte
		if err := rows.Scan(&c.Name, &c.Percentage, &uuidsJSON, &c.Value, &c.DefaultValue, &c.HashKey); err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres: remote_config scan", err)
		}
		if len(uuidsJSON) > 0 {
			var arr []string
			if err := json.Unmarshal(uuidsJSON, &arr); err != nil {
				return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres: remote_config decode uuids for "+strconv.Quote(c.Name), err)
			}
			if len(arr) > 0 {
				c.UUIDs = make(map[string]struct{}, len(arr))
				for _, u := range arr {
					c.UUIDs[u] = struct{}{}
				}
			}
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres: remote_config rows", err)
	}
	return out, nil
}

// Put inserts or replaces a row keyed by cfg.Name. Empty Name is
// rejected with the same error type the memory store uses so callers
// (admin REST handler) get a consistent shape across backends.
func (s *RemoteConfigStore) Put(ctx context.Context, cfg remoteconfig.Config) error {
	if cfg.Name == "" {
		return &remoteconfig.InvalidConfigError{Reason: "Name is required"}
	}
	if cfg.Percentage < 0 || cfg.Percentage > 100 {
		return &remoteconfig.InvalidConfigError{Reason: "Percentage must be in [0,100]"}
	}
	arr := make([]string, 0, len(cfg.UUIDs))
	for u := range cfg.UUIDs {
		arr = append(arr, u)
	}
	uuidsJSON, err := json.Marshal(arr)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: encode uuids", err)
	}

	const stmt = `
		INSERT INTO remote_config (name, percentage, uuids, value, default_value, hash_key, updated_at)
		VALUES ($1, $2, $3::jsonb, $4, $5, $6, NOW())
		ON CONFLICT (name) DO UPDATE
		   SET percentage    = EXCLUDED.percentage,
		       uuids         = EXCLUDED.uuids,
		       value         = EXCLUDED.value,
		       default_value = EXCLUDED.default_value,
		       hash_key      = EXCLUDED.hash_key,
		       updated_at    = NOW()`
	if _, err := s.q.Exec(ctx, stmt, cfg.Name, cfg.Percentage, uuidsJSON, cfg.Value, cfg.DefaultValue, cfg.HashKey); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: remote_config upsert", err)
	}
	return nil
}

// Delete removes a row by name. Missing rows are not an error —
// SQL DELETE returns zero rows affected (no error) on a missing
// key, which matches the in-memory store's idempotent contract.
func (s *RemoteConfigStore) Delete(ctx context.Context, name string) error {
	if name == "" {
		return nil
	}
	if _, err := s.q.Exec(ctx, `DELETE FROM remote_config WHERE name = $1`, name); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres: remote_config delete", err)
	}
	return nil
}
