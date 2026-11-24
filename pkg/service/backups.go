package service

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/backups"
)

// BackupService defines the message-archive operations exposed to REST and
// gRPC handlers. The interface bundles two underlying managers (an
// account-authenticated [backups.AuthManager] for credential issuance and
// a ZK-authenticated [backups.Manager] for archive operations) so handlers
// only depend on a single seam.
//
// Two auth models are present and handlers must call the appropriate
// helper:
//
//   - Account-authenticated calls (SetBackupID, GetBackupIDLimits,
//     RedeemReceipt, GetBackupAuthCredentials) take an accountUUID + deviceID
//     extracted from the Signal session by middleware.
//
//   - ZK-authenticated calls (everything else) take an [*backups.AuthenticatedUser]
//     produced by [BackupService.AuthenticateBackupUser]. Handlers extract
//     the BackupAuthCredentialPresentation + XEd25519 signature from the
//     anonymous request, call AuthenticateBackupUser once at the top of the
//     handler, and pass the result into subsequent calls.
type BackupService interface {

	// --- Account-authenticated --------------------------------------------

	// SetBackupID commits the blinded backup-id(s) for the account. Only
	// the primary device may set backup-ids.
	SetBackupID(ctx context.Context, accountUUID string, deviceID uint64, req backups.SetBackupIDRequest) error

	// GetBackupIDLimits reports when the account may next rotate its
	// backup-id(s).
	GetBackupIDLimits(ctx context.Context, accountUUID string) (*backups.BackupIDLimits, error)

	// RedeemReceipt redeems a paid-tier receipt presentation, marking the
	// account as eligible for the paid backup tier.
	RedeemReceipt(ctx context.Context, accountUUID string, req backups.RedeemReceiptRequest) error

	// GetBackupAuthCredentials issues backup-auth credentials covering the
	// half-open window [redemptionStart, redemptionEnd). Each day in the
	// window is issued separately. The maximum window is 7 days; longer
	// windows are rejected with [*backups.InvalidArgumentError].
	GetBackupAuthCredentials(
		ctx context.Context,
		accountUUID string,
		redemptionStart time.Time,
		redemptionEnd time.Time,
	) (*backups.CredentialsResponse, error)

	// --- ZK-authenticated -------------------------------------------------

	// AuthenticateBackupUser verifies a presentation + signature against
	// the stored public key for the encoded backup-id. The returned
	// [*backups.AuthenticatedUser] must be passed into all subsequent
	// ZK-authenticated calls. Returns [*backups.FailedZkAuthError] on
	// verification failure.
	AuthenticateBackupUser(
		ctx context.Context,
		presentation []byte,
		signature []byte,
		userAgent string,
	) (*backups.AuthenticatedUser, error)

	// SetPublicKey registers the XEd25519 public key for the presented
	// backup-id. May only be called once per backup-id; subsequent
	// attempts with a different key return [*backups.PublicKeyConflictError].
	SetPublicKey(
		ctx context.Context,
		presentation []byte,
		signature []byte,
		publicKey []byte,
	) error

	// BackupInfo returns the per-user CDN paths plus the current
	// usage figure for an existing backup.
	BackupInfo(ctx context.Context, user *backups.AuthenticatedUser) (*backups.Info, error)

	// TTLRefresh stamps the last-refresh timestamp so the backup is not
	// reaped by the [RemoveExpiredBackups] worker.
	TTLRefresh(ctx context.Context, user *backups.AuthenticatedUser) error

	// CreateMessageBackupUploadDescriptor mints a resumable-upload form
	// for the message-backup blob. Requires the messages credential type.
	CreateMessageBackupUploadDescriptor(
		ctx context.Context,
		user *backups.AuthenticatedUser,
	) (*backups.UploadDescriptor, error)

	// CreateTemporaryAttachmentUploadDescriptor mints a resumable-upload
	// form for a temporary attachment that the client will subsequently
	// re-encrypt and copy to backup via [CopyToBackup]. Requires the
	// media credential type and the paid tier.
	CreateTemporaryAttachmentUploadDescriptor(
		ctx context.Context,
		user *backups.AuthenticatedUser,
	) (*backups.UploadDescriptor, error)

	// GenerateReadAuth returns the request headers a client must include
	// to read backup objects from the given CDN. Currently only CDN 3 is
	// supported.
	GenerateReadAuth(
		ctx context.Context,
		user *backups.AuthenticatedUser,
		cdnNumber int,
	) (map[string]string, error)

	// GenerateSVRBAuth returns credentials for the SVRB service (used by
	// clients for forward-secrecy of the messages backup). Requires the
	// messages credential type.
	GenerateSVRBAuth(
		ctx context.Context,
		user *backups.AuthenticatedUser,
	) (*backups.ExternalServiceCredentials, error)

	// GetCopyQuota returns a [backups.CopyQuota] partitioning the
	// requested copies into those that fit in the remaining media quota
	// and those that must be rejected with [backups.CopyOutcomeOutOfQuota].
	GetCopyQuota(
		ctx context.Context,
		user *backups.AuthenticatedUser,
		toCopy []backups.CopyParameters,
	) (*backups.CopyQuota, error)

	// CopyToBackup performs the copies in the supplied quota, invoking
	// fn for each per-item result. Returning a non-nil error from fn
	// aborts iteration.
	CopyToBackup(
		ctx context.Context,
		quota backups.CopyQuota,
		fn func(backups.CopyResult) error,
	) error

	// ListMedia returns one page of the user's stored media descriptors.
	// cursor is passed through unchanged from a previous result; nil
	// starts from the beginning.
	ListMedia(
		ctx context.Context,
		user *backups.AuthenticatedUser,
		cursor *string,
		limit int,
	) (*backups.ListMediaResult, error)

	// DeleteMedia removes the supplied descriptors, invoking fn for each
	// successfully deleted item. The quota update is batched and applied
	// once the iteration completes.
	DeleteMedia(
		ctx context.Context,
		user *backups.AuthenticatedUser,
		descriptors []backups.StorageDescriptor,
		fn func(backups.StorageDescriptor) error,
	) error

	// DeleteEntireBackup schedules the user's entire backup (messages +
	// media + SVRB state) for deletion. The CDN deletion runs
	// asynchronously via the [RemoveExpiredBackups] worker; on conflict
	// with a pending deletion the call performs a synchronous fallback.
	DeleteEntireBackup(ctx context.Context, user *backups.AuthenticatedUser) error

	// --- Worker-facing ----------------------------------------------------

	// ListBackupAttributes streams every backup row to fn. Used by the
	// [BackupUsageRecalculation] worker.
	ListBackupAttributes(
		ctx context.Context,
		segments int,
		fn func(backups.StoredAttributes) error,
	) error

	// GetExpiredBackups streams every backup whose last-refresh (or
	// last-media-refresh) is strictly before purgeTime. Used by the
	// [RemoveExpiredBackups] worker.
	GetExpiredBackups(
		ctx context.Context,
		segments int,
		purgeTime time.Time,
		fn func(backups.ExpiredBackup) error,
	) error

	// ExpireBackup deletes the CDN prefix referenced by expired and
	// clears the metadata row. Used by the [RemoveExpiredBackups] worker.
	ExpireBackup(ctx context.Context, expired backups.ExpiredBackup) error

	// RecalculateQuota re-lists the media prefix on the CDN, writes the
	// fresh usage figure to the store, and returns the before/after
	// values. Used by the [BackupUsageRecalculation] worker.
	RecalculateQuota(
		ctx context.Context,
		attrs backups.StoredAttributes,
	) (*backups.RecalculationResult, error)
}

// NewBackupService returns a [BackupService] backed by the supplied
// [backups.Service] (which itself bundles a [backups.Manager] and
// [backups.AuthManager]). The constructor mirrors NewKeyService /
// NewMessageService: protocol handlers only depend on the interface;
// composition of the underlying managers lives in cmd/signald/start.go.
func NewBackupService(service *backups.Service) BackupService {
	return service
}
