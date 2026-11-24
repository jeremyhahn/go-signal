// Package attachments provides storage for media attachments (CDN content).
package attachments

import (
	"context"
	"io"
)

// Store is streaming attachment (CDN) storage.
type Store interface {
	// Put stores an attachment. The caller provides a reader and the
	// expected size. The key uniquely identifies the attachment.
	Put(ctx context.Context, key string, data io.Reader, size int64) error

	// Get retrieves an attachment. Returns a reader, the size in bytes,
	// and any error. The caller must close the returned reader.
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)

	// Delete removes an attachment.
	Delete(ctx context.Context, key string) error

	// Exists reports whether an attachment exists.
	Exists(ctx context.Context, key string) (bool, error)
}
