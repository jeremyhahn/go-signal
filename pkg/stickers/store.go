package stickers

import "context"

// PackStore persists sticker-pack metadata so the server can audit
// uploader → pack relationships later. Implementations are pluggable
// across the supported storage backends (memory / qrdb / postgres).
//
// The pack contents themselves live on the CDN; this store only holds the
// pack ID + uploader UUID + timestamp.
type PackStore interface {
	// Put records that accountUUID issued an upload form for packID. Safe
	// to call multiple times for the same packID; the implementation may
	// overwrite or no-op as long as the (packID, accountUUID) mapping is
	// observable via Get.
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
