package backups

import (
	"context"
	"time"
)

// Store is the backup metadata contract per backend; methods take the raw [BackupID] and hash it with SHA-256 themselves. Safe for concurrent use.
type Store interface {
	// SetPublicKey registers the XEd25519 key and level for a backup-id; a different key is [*PublicKeyConflictError].
	SetPublicKey(ctx context.Context, id BackupID, level BackupLevel, publicKey []byte) error

	// RetrieveAuthenticationData returns the public key and CDN directories; ok=false means no row, a verification failure.
	RetrieveAuthenticationData(ctx context.Context, id BackupID) (data *AuthenticationData, ok bool, err error)

	// AddMessageBackup records that an upload form has been issued for the
	// message-backup slot, refreshing the last-refresh timestamp. Idempotent.
	AddMessageBackup(ctx context.Context, user AuthenticatedUser) error

	// TTLRefresh updates the last-refresh and (if the credential type is
	// media) last-media-refresh timestamps, returning the current row.
	// Returns [*NotFoundError] if no row exists.
	TTLRefresh(ctx context.Context, user AuthenticatedUser) (*StoredAttributes, error)

	// DescribeBackup returns the dynamic per-row info needed to assemble a
	// [Info] response: the CDN number and (for media credentials) the
	// current usage figure.
	DescribeBackup(ctx context.Context, user AuthenticatedUser) (*Description, error)

	// TrackMedia atomically adjusts media bytes and object counters; negative deltas refund quota.
	TrackMedia(ctx context.Context, user AuthenticatedUser, countDelta, bytesDelta int64) error

	// GetMediaUsage returns the current cached usage figure together with
	// the wall-clock time it was last reconciled against the CDN listing.
	GetMediaUsage(ctx context.Context, user AuthenticatedUser) (*TimestampedUsageInfo, error)

	// SetMediaUsage overwrites the cached usage figure (used after a full
	// re-list of the media prefix on the CDN). Stamps lastRecalculationTime
	// at the implementation's clock.
	SetMediaUsage(ctx context.Context, user AuthenticatedUser, usage UsageInfo) error

	// SetMediaUsageFor is [Store.SetMediaUsage] for a [StoredAttributes] row, for the recalculation worker.
	SetMediaUsageFor(ctx context.Context, attrs StoredAttributes, usage UsageInfo) error

	// ScheduleBackupDeletion swaps in fresh directories and queues the old ones for expiry; [*PendingDeletionError] if one is queued.
	ScheduleBackupDeletion(ctx context.Context, user AuthenticatedUser) error

	// StartExpiration marks an [ExpiredBackup] row as in-progress so the
	// worker has lease semantics over the deletion.
	StartExpiration(ctx context.Context, expired ExpiredBackup) error

	// FinishExpiration clears the expired-prefix marker after the CDN
	// prefix has been fully deleted.
	FinishExpiration(ctx context.Context, expired ExpiredBackup) error

	// ListBackupAttributes streams every row to fn; an error aborts. segments is a parallelism hint backends may ignore.
	ListBackupAttributes(ctx context.Context, segments int, fn func(StoredAttributes) error) error

	// GetExpiredBackups streams every backup whose last-refresh (or
	// last-media-refresh) is strictly before purgeTime to the supplied
	// callback. See [ExpirationType] for the per-row classification.
	GetExpiredBackups(ctx context.Context, segments int, purgeTime time.Time, fn func(ExpiredBackup) error) error
}

// RedeemedReceiptsStore records redeemed receipt serials so one receipt extends only one account's voucher.
type RedeemedReceiptsStore interface {
	// Put records serial as redeemed until expiration and reports whether this is the first redemption.
	Put(ctx context.Context, receiptSerial []byte, expiration time.Time, receiptLevel uint64, accountUUID string) (bool, error)
}
