package backups

import (
	"context"
	"time"
)

// Store is the metadata-storage contract for backups. Each persistence
// backend (memory, qrdb, postgres) implements this directly. Mirrors the
// surface of Java Signal-Server's BackupsDb DynamoDB adapter.
//
// All methods accept the un-hashed [BackupID] from the credential; the
// implementation is responsible for applying the canonical SHA-256 hash
// before keying into storage. This keeps the hashing rule (Java's
// BackupsDb.hashedBackupId) in one place — the backend — and prevents
// callers from accidentally double-hashing.
//
// Implementations must be safe for concurrent use.
type Store interface {
	// SetPublicKey registers the XEd25519 public key that subsequent
	// presentations of this backup-id must be signed with. The level is
	// recorded so the same backup-id cannot be silently upgraded or
	// downgraded later.
	//
	// Returns [*PublicKeyConflictError] if a different public key is already
	// registered for this backup-id.
	SetPublicKey(ctx context.Context, id BackupID, level BackupLevel, publicKey []byte) error

	// RetrieveAuthenticationData returns the public key + per-user CDN
	// directories needed to authenticate a presentation. ok=false means
	// no row exists yet for this backup-id; callers should treat that
	// as a verification failure rather than a hard error.
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

	// TrackMedia atomically adjusts the media bytes-used + object-count
	// counters. Negative deltas are used after deletes and after failed
	// copy operations to refund quota. Implementations must apply the
	// update atomically with respect to other TrackMedia calls.
	TrackMedia(ctx context.Context, user AuthenticatedUser, countDelta, bytesDelta int64) error

	// GetMediaUsage returns the current cached usage figure together with
	// the wall-clock time it was last reconciled against the CDN listing.
	GetMediaUsage(ctx context.Context, user AuthenticatedUser) (*TimestampedUsageInfo, error)

	// SetMediaUsage overwrites the cached usage figure (used after a full
	// re-list of the media prefix on the CDN). Stamps lastRecalculationTime
	// at the implementation's clock.
	SetMediaUsage(ctx context.Context, user AuthenticatedUser, usage UsageInfo) error

	// SetMediaUsageFor is the worker-side variant of [Store.SetMediaUsage]
	// that operates on a [StoredAttributes] row obtained from
	// [Store.ListBackupAttributes]; used by the usage-recalculation worker
	// where there is no [AuthenticatedUser] available.
	SetMediaUsageFor(ctx context.Context, attrs StoredAttributes, usage UsageInfo) error

	// ScheduleBackupDeletion swaps the backupDir / mediaDir pointers so
	// future authentications see fresh empty directories; the old prefixes
	// are queued for the expiration worker. Returns
	// [*PendingDeletionError] if a swap is already queued.
	ScheduleBackupDeletion(ctx context.Context, user AuthenticatedUser) error

	// StartExpiration marks an [ExpiredBackup] row as in-progress so the
	// worker has lease semantics over the deletion.
	StartExpiration(ctx context.Context, expired ExpiredBackup) error

	// FinishExpiration clears the expired-prefix marker after the CDN
	// prefix has been fully deleted.
	FinishExpiration(ctx context.Context, expired ExpiredBackup) error

	// ListBackupAttributes streams every row in the backups table to the
	// supplied callback. Returning a non-nil error from the callback
	// aborts iteration. segments hints at how many partitions to read in
	// parallel (>= 1); backends free to ignore for non-DDB stores.
	ListBackupAttributes(ctx context.Context, segments int, fn func(StoredAttributes) error) error

	// GetExpiredBackups streams every backup whose last-refresh (or
	// last-media-refresh) is strictly before purgeTime to the supplied
	// callback. See [ExpirationType] for the per-row classification.
	GetExpiredBackups(ctx context.Context, segments int, purgeTime time.Time, fn func(ExpiredBackup) error) error
}

// RedeemedReceiptsStore tracks ZK receipt-credential serials that have
// already been redeemed, ensuring a single receipt cannot extend the
// backup voucher of more than one account. Mirrors Java's
// RedeemedReceiptsManager. Implemented per-backend in pkg/storage/.
type RedeemedReceiptsStore interface {
	// Put attempts to record the receipt serial as redeemed by accountUUID
	// with the supplied expiration and receipt level. Returns true on
	// first redemption, false if the same serial was already redeemed
	// (regardless of which account); callers translate false into a
	// [*BadReceiptError] for the client. Implementations enforce TTL
	// against expiration so reused serials past their natural expiry
	// fall out of the dedup set.
	Put(ctx context.Context, receiptSerial []byte, expiration time.Time, receiptLevel uint64, accountUUID string) (bool, error)
}
