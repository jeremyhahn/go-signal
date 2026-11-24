package stickers

import "context"

// PackStore records pack ID, uploader UUID and time; the pack contents live on the CDN.
type PackStore interface {
	// Put records that accountUUID issued a form for packID; repeated calls are allowed.
	Put(ctx context.Context, meta *PackMetadata) error

	// Get returns the metadata for packID or a typed not-found error
	// when the pack hasn't been issued.
	Get(ctx context.Context, packID string) (*PackMetadata, error)
}

// MemoryPackStore is an in-memory PackStore. Used in dev + tests; not a
// production store (no persistence across restarts).
type MemoryPackStore struct {
	packs map[string]*PackMetadata
}

// NewMemoryPackStore returns an empty MemoryPackStore.
func NewMemoryPackStore() *MemoryPackStore {
	return &MemoryPackStore{packs: make(map[string]*PackMetadata)}
}

// Put records meta in the in-memory map.
func (s *MemoryPackStore) Put(_ context.Context, meta *PackMetadata) error {
	if meta == nil || meta.PackID == "" {
		return &InvalidPackError{Reason: "PackID is required"}
	}
	clone := *meta
	s.packs[meta.PackID] = &clone
	return nil
}

// Get returns the metadata for packID or *PackNotFoundError.
func (s *MemoryPackStore) Get(_ context.Context, packID string) (*PackMetadata, error) {
	meta, ok := s.packs[packID]
	if !ok {
		return nil, &PackNotFoundError{PackID: packID}
	}
	clone := *meta
	return &clone, nil
}
