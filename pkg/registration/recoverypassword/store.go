package recoverypassword

import (
	"context"
	"time"
)

// Store keeps SaltedTokenHash entries by lowercase PNI UUID; expired entries must read as NotFoundError.
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
