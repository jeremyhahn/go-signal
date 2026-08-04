package backups

import "context"

// BlobStore is the remote-storage contract for backup content. Each CDN
// adapter (local filesystem for dev, S3, GCS, ...) implements this. Mirrors
// the surface of Java Signal-Server's RemoteStorageManager interface.
//
// Concrete adapters live under pkg/storage/blob/. The [Service] composes a
// [BlobStore] with a [Store] (metadata) to form the full backup subsystem.
//
// All paths are CDN-relative; the [Service] is responsible for prefixing
// with the user's backupDir / mediaDir before calling.
type BlobStore interface {
	// CDNNumber identifies which CDN this adapter speaks to. Surfaced to
	// clients in [Info.CDN] and [StorageDescriptor.CDN]; clients refuse
	// to operate on descriptors for unknown CDN numbers.
	CDNNumber() int

	// GenerateUpload mints a resumable-upload form for the given key
	// (relative to the CDN root). The form's signedUploadLocation is
	// suitable for direct TUS / pre-signed upload by the client.
	GenerateUpload(ctx context.Context, key string) (*UploadDescriptor, error)

	// ReadHeaders returns the request headers a client must include to
	// read objects under the given prefix (typically the user's
	// backupDir). The map is fresh per call; callers may mutate.
	ReadHeaders(ctx context.Context, prefix string) (map[string]string, error)

	// Copy fetches the source object from sourceCDN, re-encrypts it under
	// the supplied [MediaEncryptionParameters], and stores it at destPath
	// on this CDN. Returns [*SourceNotFoundError] / [*InvalidLengthError]
	// if the source cannot be validated; the [Service] aggregator maps
	// those to [CopyOutcomeSourceNotFound] / [CopyOutcomeSourceWrongLength].
	Copy(
		ctx context.Context,
		sourceCDN int,
		sourceKey string,
		sourceLength int,
		params MediaEncryptionParameters,
		destPath string,
	) error

	// Delete removes a single object and returns the byte-length that was
	// freed; the [Service] uses the returned delta to refund quota.
	// Returns 0 (no error) if the object did not exist.
	Delete(ctx context.Context, path string) (int64, error)

	// List returns one page of objects under the given prefix. Cursor is
	// passed through unchanged from a previous result; limit is a hint
	// the CDN is free to clamp.
	List(ctx context.Context, prefix string, cursor *string, limit int) (*BlobListResult, error)

	// CalculateBytesUsed walks the entire prefix and returns the
	// aggregate byte count + object count. Used by the
	// [Service.RecalculateQuota] worker path; should not be called on
	// the request path.
	CalculateBytesUsed(ctx context.Context, prefix string) (UsageInfo, error)
}
