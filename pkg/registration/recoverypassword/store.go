package recoverypassword

import (
	"context"
	"time"
)

// Store persists SaltedTokenHash entries keyed by phone number identifier
// (PNI). Implementations are expected to honor a per-entry expiration so that
// stale recovery passwords self-evict; entries past their expiration MUST be
// reported as NotFoundError on Get.
//
// PNI is encoded as a canonical lowercase UUID string (matching Java's
// `UUID.toString()`). Manager validates the input before reaching the Store,
// so backends may treat the value as opaque.
type Store interface {
	// Get returns the salted hash currently stored for pni, or NotFoundError
	// if none exists or the entry has expired.
	Get(ctx context.Context, pni string) (*SaltedTokenHash, error)

	// Put atomically inserts or replaces the entry for pni. The expiresAt
	// instant supplies the absolute deadline after which Get must treat the
	// row as missing.
	Put(ctx context.Context, pni string, hash *SaltedTokenHash, expiresAt time.Time) error

	// Delete removes the entry for pni. It MUST be idempotent: deleting a
	// non-existent entry returns nil.
	Delete(ctx context.Context, pni string) error
}
