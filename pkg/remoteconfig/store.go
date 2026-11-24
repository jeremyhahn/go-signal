package remoteconfig

import (
	"context"
	"sort"
	"sync"
)

// Store persists dynamic configuration. Implementations are pluggable
// across the supported backends (memory / postgres). The interface is
// intentionally minimal — admin write operations live alongside reads so
// the same store can back both the public /v2/config endpoint and the
// internal admin tooling.
type Store interface {
	// GetAll returns every config row in deterministic order (by Name).
	GetAll(ctx context.Context) ([]Config, error)
	// Put inserts or replaces a row keyed by cfg.Name. Validation happens
	// at the caller (REST admin handler); the store enforces only the
	// non-empty-name invariant.
	Put(ctx context.Context, cfg Config) error
	// Delete removes a row by name. Idempotent.
	Delete(ctx context.Context, name string) error
}

// MemoryStore is an in-memory Store. Tests + dev use this; production
// deployments back the same interface with PostgresStore.
type MemoryStore struct {
	mu   sync.RWMutex
	rows map[string]Config
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{rows: make(map[string]Config)}
}

// GetAll implements Store.
func (s *MemoryStore) GetAll(_ context.Context) ([]Config, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Config, 0, len(s.rows))
	for _, c := range s.rows {
		out = append(out, cloneConfig(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Put implements Store.
func (s *MemoryStore) Put(_ context.Context, cfg Config) error {
	if cfg.Name == "" {
		return &InvalidConfigError{Reason: "Name is required"}
	}
	if cfg.Percentage < 0 || cfg.Percentage > 100 {
		return &InvalidConfigError{Reason: "Percentage must be in [0,100]"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[cfg.Name] = cloneConfig(cfg)
	return nil
}

// Delete implements Store.
func (s *MemoryStore) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, name)
	return nil
}

// cloneConfig deep-copies a Config so concurrent readers see a stable
// view even when the store is mutated.
func cloneConfig(c Config) Config {
	if c.UUIDs != nil {
		uuids := make(map[string]struct{}, len(c.UUIDs))
		for k := range c.UUIDs {
			uuids[k] = struct{}{}
		}
		c.UUIDs = uuids
	}
	return c
}

// InvalidConfigError indicates the caller supplied a Config that fails
// validation (empty Name, out-of-range Percentage). Stores return it from
// Put; the admin REST handler maps it to HTTP 400.
type InvalidConfigError struct {
	Reason string
}

// Error implements the error interface.
func (e *InvalidConfigError) Error() string {
	return "remoteconfig: invalid config: " + e.Reason
}
