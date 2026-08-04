package backups

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/limits"
)

// SVRBCredentialGenerator issues per-user credentials for the SVRB
// (Secure Value Recovery for Backups) service. Implementations live in the
// SVRB integration layer; pkg/backups provides a disabled default for
// deployments that don't run SVRB yet.
type SVRBCredentialGenerator interface {
	GenerateFor(ctx context.Context, svrbID string) (*ExternalServiceCredentials, error)
}

// SVRBClient performs server-side maintenance against the SVRB service.
// Today only the delete path is needed (called from DeleteEntireBackup so
// SVRB state does not outlive the user's backup). Real implementations
// land alongside the SVRB binary in Phase 4.
type SVRBClient interface {
	RemoveData(ctx context.Context, svrbID string) error
}

// disabledSVRBGenerator is the default for deployments without an SVRB
// service. GenerateFor returns an error so REST/gRPC handlers naturally
// translate to a 503-equivalent.
type disabledSVRBGenerator struct{}

// GenerateFor always returns an error indicating SVRB is not configured.
func (disabledSVRBGenerator) GenerateFor(context.Context, string) (*ExternalServiceCredentials, error) {
	return nil, errors.New("SVRB credential generator not configured")
}

// disabledSVRBClient is the default for deployments without SVRB.
// RemoveData is a no-op so DeleteEntireBackup is not blocked on SVRB
// availability.
type disabledSVRBClient struct{}

// RemoveData is a no-op.
func (disabledSVRBClient) RemoveData(context.Context, string) error { return nil }

// NewDisabledSVRBCredentialGenerator returns the default no-op generator
// for deployments that haven't wired SVRB yet. Suitable for tests and
// dev environments.
func NewDisabledSVRBCredentialGenerator() SVRBCredentialGenerator {
	return disabledSVRBGenerator{}
}

// NewDisabledSVRBClient returns the default no-op SVRB client.
func NewDisabledSVRBClient() SVRBClient {
	return disabledSVRBClient{}
}

// Manager handles the ZK-authenticated half of the backup subsystem:
// authenticating presentations, registering public keys, reading/writing
// backup info, brokering CDN copy/list/delete operations, and refreshing
// TTLs. Mirrors Java's BackupManager.
type Manager struct {
	store              Store
	blob               BlobStore
	serverSecretParams *zkgroup.GenericServerSecretParams
	attachmentLimiter  limits.RateLimiter
	svrb               SVRBCredentialGenerator
	svrbClient         SVRBClient
	clock              func() time.Time
	maxQuota           int64
}

// ManagerOptions configures a [Manager].
type ManagerOptions struct {
	// Store and BlobStore are required.
	Store Store
	Blob  BlobStore
	// ServerSecretParams verifies BackupAuthCredentialPresentations.
	ServerSecretParams *zkgroup.GenericServerSecretParams
	// AttachmentLimiter rate-limits CreateTemporaryAttachmentUploadDescriptor.
	// Keyed by base64(hashedBackupID).
	AttachmentLimiter limits.RateLimiter
	// SVRB issues per-user credentials for the SVRB service. Nil
	// defaults to [NewDisabledSVRBCredentialGenerator].
	SVRB SVRBCredentialGenerator
	// SVRBClient deletes per-user SVRB state during full-backup deletion.
	// Nil defaults to [NewDisabledSVRBClient] (no-op).
	SVRBClient SVRBClient
	// Clock is the time source; nil defaults to time.Now in UTC.
	Clock func() time.Time
	// MaxQuota caps the per-user media-backup quota (bytes). Zero
	// defaults to the Java default of 100 GiB.
	MaxQuota int64
}

// DefaultMaxQuota is the per-user media backup quota when none is configured.
// Matches Java's DynamicBackupConfiguration.maxTotalMediaSize default.
const DefaultMaxQuota int64 = 100 * 1024 * 1024 * 1024 // 100 GiB

// NewManager constructs a [Manager]. Store, Blob, and ServerSecretParams
// are required.
func NewManager(opts ManagerOptions) *Manager {
	clock := opts.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	svrb := opts.SVRB
	if svrb == nil {
		svrb = NewDisabledSVRBCredentialGenerator()
	}
	svrbClient := opts.SVRBClient
	if svrbClient == nil {
		svrbClient = NewDisabledSVRBClient()
	}
	return &Manager{
		store:              opts.Store,
		blob:               opts.Blob,
		serverSecretParams: opts.ServerSecretParams,
		attachmentLimiter:  opts.AttachmentLimiter,
		svrb:               svrb,
		svrbClient:         svrbClient,
		clock:              clock,
		maxQuota:           orDefaultInt64(opts.MaxQuota, DefaultMaxQuota),
	}
}

// hashedBackupID returns the first 16 bytes of SHA-256(id), matching Java's
// BackupsDb.hashedBackupId. The result is the canonical storage key — all
// metadata writes and rate-limit keys derive from it.
func hashedBackupID(id BackupID) []byte {
	sum := sha256.Sum256(id[:])
	out := make([]byte, 16)
	copy(out, sum[:16])
	return out
}

// rateLimitKey returns the rate-limit bucket key for a backup user
// (base64(hashedBackupID)), matching Java BackupManager.rateLimitKey.
func rateLimitKey(user *AuthenticatedUser) string {
	return base64.StdEncoding.EncodeToString(hashedBackupID(user.BackupID))
}

// svrbIdentifier returns the per-user identifier passed to the SVRB service.
// Matches Java BackupManager.svrbIdentifier (lowercase hex of hashedBackupID).
func svrbIdentifier(user *AuthenticatedUser) string {
	return hex.EncodeToString(hashedBackupID(user.BackupID))
}

// SetPublicKey registers the XEd25519 public key for the presented
// backup-id. The presentation is verified first (so we don't permanently
// bind a malformed credential), then the supplied signature is verified
// against the supplied public key (this is the single bootstrap case
// where signature verification cannot use the stored key — we are
// setting it now). Storage uses a conditional-write to reject a different
// previously-stored key.
func (m *Manager) SetPublicKey(
	ctx context.Context,
	presentationBytes []byte,
	signature []byte,
	publicKey []byte,
) error {
	if len(signature) != 64 {
		return &InvalidArgumentError{Field: "signature", Message: "must be 64 bytes"}
	}
	if len(publicKey) == 0 {
		return &InvalidArgumentError{Field: "publicKey", Message: "must not be empty"}
	}

	presentation, err := zkgroup.DeserializeBackupAuthCredentialPresentation(presentationBytes)
	if err != nil {
		return &FailedZkAuthError{Reason: "malformed presentation"}
	}
	if err := presentation.Verify(zkgroup.TimestampFromTime(m.clock()), m.serverSecretParams); err != nil {
		return &FailedZkAuthError{Reason: "presentation verification failed"}
	}

	pubKey, err := ecc.DecodePoint(publicKey, 0)
	if err != nil {
		return &InvalidArgumentError{Field: "publicKey", Message: err.Error()}
	}
	var sig [64]byte
	copy(sig[:], signature)
	if !ecc.VerifySignature(pubKey, presentationBytes, sig) {
		return &FailedZkAuthError{Reason: "signature does not verify against supplied public key"}
	}

	return m.store.SetPublicKey(ctx, presentation.GetBackupID(), presentation.GetBackupLevel(), publicKey)
}

// AuthenticateBackupUser verifies a presentation + signature against the
// stored public key for the encoded backup-id and returns an
// [AuthenticatedUser] suitable for subsequent ZK-authenticated calls.
func (m *Manager) AuthenticateBackupUser(
	ctx context.Context,
	presentationBytes []byte,
	signature []byte,
	userAgent string,
) (*AuthenticatedUser, error) {
	if len(signature) != 64 {
		return nil, &FailedZkAuthError{Reason: "signature must be 64 bytes"}
	}
	presentation, err := zkgroup.DeserializeBackupAuthCredentialPresentation(presentationBytes)
	if err != nil {
		return nil, &FailedZkAuthError{Reason: "malformed presentation"}
	}
	if err := presentation.Verify(zkgroup.TimestampFromTime(m.clock()), m.serverSecretParams); err != nil {
		return nil, &FailedZkAuthError{Reason: "presentation verification failed"}
	}

	authData, ok, err := m.store.RetrieveAuthenticationData(ctx, presentation.GetBackupID())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &FailedZkAuthError{Reason: "no public key registered for backup-id"}
	}

	pubKey, err := ecc.DecodePoint(authData.PublicKey, 0)
	if err != nil {
		return nil, &FailedZkAuthError{Reason: "stored public key is malformed"}
	}
	var sig [64]byte
	copy(sig[:], signature)
	if !ecc.VerifySignature(pubKey, presentationBytes, sig) {
		return nil, &FailedZkAuthError{Reason: "signature does not verify against stored public key"}
	}

	return &AuthenticatedUser{
		BackupID:       presentation.GetBackupID(),
		CredentialType: presentation.GetCredentialType(),
		BackupLevel:    presentation.GetBackupLevel(),
		BackupDir:      authData.BackupDir,
		MediaDir:       authData.MediaDir,
		UserAgent:      userAgent,
	}, nil
}

// BackupInfo assembles a [Info] response from the per-user directories
// (carried by the authenticated user) and the dynamic CDN + usage fields
// (read from the store).
func (m *Manager) BackupInfo(ctx context.Context, user *AuthenticatedUser) (*Info, error) {
	if err := requireLevel(user, BackupLevelFree); err != nil {
		return nil, err
	}
	desc, err := m.store.DescribeBackup(ctx, *user)
	if err != nil {
		return nil, err
	}
	return &Info{
		CDN:              desc.CDN,
		BackupDir:        user.BackupDir,
		MediaDir:         user.MediaDir,
		MessageBackupKey: MessageBackupName,
		MediaUsedSpace:   desc.MediaUsedSpace,
	}, nil
}

// TTLRefresh stamps the last-refresh timestamps on the backup row.
func (m *Manager) TTLRefresh(ctx context.Context, user *AuthenticatedUser) error {
	if err := requireLevel(user, BackupLevelFree); err != nil {
		return err
	}
	_, err := m.store.TTLRefresh(ctx, *user)
	return err
}

// CreateMessageBackupUploadDescriptor mints an upload form for the
// message-backup blob.
func (m *Manager) CreateMessageBackupUploadDescriptor(
	ctx context.Context,
	user *AuthenticatedUser,
) (*UploadDescriptor, error) {
	if err := requireLevel(user, BackupLevelFree); err != nil {
		return nil, err
	}
	if err := requireCredentialType(user, CredentialTypeMessages); err != nil {
		return nil, err
	}
	if err := m.store.AddMessageBackup(ctx, *user); err != nil {
		return nil, err
	}
	return m.blob.GenerateUpload(ctx, cdnMessageBackupName(user))
}

// CreateTemporaryAttachmentUploadDescriptor mints an upload form for a
// temporary attachment the client will later copy to backup via
// [Manager.CopyToBackup]. Rate-limited per-backup-user.
func (m *Manager) CreateTemporaryAttachmentUploadDescriptor(
	ctx context.Context,
	user *AuthenticatedUser,
) (*UploadDescriptor, error) {
	if err := requireLevel(user, BackupLevelPaid); err != nil {
		return nil, err
	}
	if err := requireCredentialType(user, CredentialTypeMedia); err != nil {
		return nil, err
	}
	if m.attachmentLimiter != nil {
		if err := m.attachmentLimiter.Allow(ctx, rateLimitKey(user)); err != nil {
			return nil, err
		}
	}
	var raw [15]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	key := base64.URLEncoding.EncodeToString(raw[:])
	return m.blob.GenerateUpload(ctx, key)
}

// GenerateReadAuth returns the headers a client needs to read backup
// objects directly from the CDN.
func (m *Manager) GenerateReadAuth(
	ctx context.Context,
	user *AuthenticatedUser,
	cdnNumber int,
) (map[string]string, error) {
	if err := requireLevel(user, BackupLevelFree); err != nil {
		return nil, err
	}
	if cdnNumber != m.blob.CDNNumber() {
		return nil, &InvalidArgumentError{Field: "cdn", Message: "unsupported CDN number"}
	}
	return m.blob.ReadHeaders(ctx, user.BackupDir)
}

// GenerateSVRBAuth issues SVRB service credentials. Requires the messages
// credential type (clients only use SVRB with the messages backup-id).
func (m *Manager) GenerateSVRBAuth(ctx context.Context, user *AuthenticatedUser) (*ExternalServiceCredentials, error) {
	if err := requireLevel(user, BackupLevelFree); err != nil {
		return nil, err
	}
	if err := requireCredentialType(user, CredentialTypeMessages); err != nil {
		return nil, err
	}
	return m.svrb.GenerateFor(ctx, svrbIdentifier(user))
}

// GetCopyQuota splits a batch of copy requests into those that fit in the
// remaining media quota and those that must be rejected. If the cached
// usage indicates no remaining quota, the user's actual usage is
// recalculated against the CDN once before any reject occurs (matching
// Java's "double-check before forbidding" semantic).
func (m *Manager) GetCopyQuota(
	ctx context.Context,
	user *AuthenticatedUser,
	toCopy []CopyParameters,
) (*CopyQuota, error) {
	if err := requireLevel(user, BackupLevelPaid); err != nil {
		return nil, err
	}
	if err := requireCredentialType(user, CredentialTypeMedia); err != nil {
		return nil, err
	}
	for _, p := range toCopy {
		if p.SourceLength < 0 || int64(p.SourceLength) > MaxMediaObjectSize {
			return nil, &InvalidArgumentError{Field: "sourceLength", Message: "out of range"}
		}
	}

	info, err := m.store.GetMediaUsage(ctx, *user)
	if err != nil {
		return nil, err
	}

	remaining := m.maxQuota - info.Usage.BytesUsed
	totalAdd := int64(0)
	for _, p := range toCopy {
		totalAdd += p.DestinationObjectSize()
	}
	canStore := remaining >= totalAdd
	if canStore {
		return makeCopyQuota(*user, toCopy, remaining), nil
	}

	// Hard recalculation against the CDN before rejecting anyone — the
	// cached usage may be stale.
	usage, err := m.blob.CalculateBytesUsed(ctx, cdnMediaDirectory(user))
	if err != nil {
		return nil, err
	}
	if err := m.store.SetMediaUsage(ctx, *user, usage); err != nil {
		return nil, err
	}
	return makeCopyQuota(*user, toCopy, m.maxQuota-usage.BytesUsed), nil
}

// CopyToBackup performs the copies in quota, invoking fn for each per-item
// result. Successful copies update the quota; failures with explicit copy
// outcomes (source-not-found, source-wrong-length) refund the
// pre-reserved bytes.
func (m *Manager) CopyToBackup(ctx context.Context, quota CopyQuota, fn func(CopyResult) error) error {
	cdn := m.blob.CDNNumber()
	for _, params := range quota.RequestsToCopy {
		// Reserve quota first so we can refund on failure.
		if err := m.store.TrackMedia(ctx, quota.User, 1, params.DestinationObjectSize()); err != nil {
			return err
		}
		destPath := cdnMediaPath(&quota.User, params.DestinationMediaID)
		copyErr := m.blob.Copy(ctx, params.SourceCDN, params.SourceKey, params.SourceLength, params.EncryptionParameters, destPath)
		if copyErr == nil {
			if err := fn(CopyResult{Outcome: CopyOutcomeSuccess, MediaID: params.DestinationMediaID, CDN: &cdn}); err != nil {
				return err
			}
			continue
		}
		outcome, mapped := classifyCopyError(copyErr)
		if !mapped {
			// Propagate unexpected errors and refund the reservation.
			_ = m.store.TrackMedia(ctx, quota.User, -1, -params.DestinationObjectSize())
			return copyErr
		}
		_ = m.store.TrackMedia(ctx, quota.User, -1, -params.DestinationObjectSize())
		if err := fn(CopyResult{Outcome: outcome, MediaID: params.DestinationMediaID}); err != nil {
			return err
		}
	}
	for _, params := range quota.ToReject {
		if err := fn(CopyResult{Outcome: CopyOutcomeOutOfQuota, MediaID: params.DestinationMediaID}); err != nil {
			return err
		}
	}
	return nil
}

// ListMedia returns one page of the user's stored media descriptors.
func (m *Manager) ListMedia(
	ctx context.Context,
	user *AuthenticatedUser,
	cursor *string,
	limit int,
) (*ListMediaResult, error) {
	if err := requireLevel(user, BackupLevelFree); err != nil {
		return nil, err
	}
	result, err := m.blob.List(ctx, cdnMediaDirectory(user), cursor, limit)
	if err != nil {
		return nil, err
	}
	cdn := m.blob.CDNNumber()
	out := &ListMediaResult{Cursor: result.Cursor, Media: make([]StorageDescriptorWithLength, 0, len(result.Objects))}
	for _, obj := range result.Objects {
		key, err := decodeMediaIDFromCDN(obj.Key)
		if err != nil {
			return nil, err
		}
		out.Media = append(out.Media, StorageDescriptorWithLength{CDN: cdn, Key: key, Length: obj.Length})
	}
	return out, nil
}

// DeleteMedia removes the supplied descriptors, invoking fn for each
// successfully deleted item. Quota updates are batched: every 100 deletes
// flushes a TrackMedia call, with a final flush at the end.
func (m *Manager) DeleteMedia(
	ctx context.Context,
	user *AuthenticatedUser,
	descriptors []StorageDescriptor,
	fn func(StorageDescriptor) error,
) error {
	if err := requireLevel(user, BackupLevelFree); err != nil {
		return err
	}
	if err := requireCredentialType(user, CredentialTypeMedia); err != nil {
		return err
	}
	cdn := m.blob.CDNNumber()
	for _, sd := range descriptors {
		if sd.CDN != cdn {
			return &InvalidArgumentError{Field: "cdn", Message: "unsupported CDN"}
		}
	}

	const checkpointCount = 100
	var (
		countDelta int64
		bytesDelta int64
	)
	flush := func() error {
		if countDelta == 0 && bytesDelta == 0 {
			return nil
		}
		err := m.store.TrackMedia(ctx, *user, countDelta, bytesDelta)
		countDelta = 0
		bytesDelta = 0
		return err
	}
	for _, sd := range descriptors {
		freed, err := m.blob.Delete(ctx, cdnMediaPath(user, sd.Key))
		if err != nil {
			_ = flush()
			return err
		}
		countDelta--
		bytesDelta -= freed
		if -countDelta >= checkpointCount {
			if err := flush(); err != nil {
				return err
			}
		}
		if err := fn(sd); err != nil {
			_ = flush()
			return err
		}
	}
	return flush()
}

// DeleteEntireBackup schedules the user's backup for deletion. If a
// previous deletion is already pending (the swap raced), falls back to a
// synchronous purge of the existing prefix.
func (m *Manager) DeleteEntireBackup(ctx context.Context, user *AuthenticatedUser) error {
	if err := requireLevel(user, BackupLevelFree); err != nil {
		return err
	}
	// SVRB rows are only attached to messages credentials; remove before
	// the swap. The disabled default is a no-op so deployments without
	// SVRB don't block on this call.
	if user.CredentialType == CredentialTypeMessages {
		if err := m.svrbClient.RemoveData(ctx, svrbIdentifier(user)); err != nil {
			return err
		}
	}
	err := m.store.ScheduleBackupDeletion(ctx, *user)
	var pending *PendingDeletionError
	if err != nil && errors.As(err, &pending) {
		return m.deletePrefix(ctx, user.BackupDir)
	}
	return err
}

// --- worker-facing helpers --------------------------------------------------

// ListBackupAttributes streams every backup row to fn.
func (m *Manager) ListBackupAttributes(
	ctx context.Context,
	segments int,
	fn func(StoredAttributes) error,
) error {
	return m.store.ListBackupAttributes(ctx, segments, fn)
}

// GetExpiredBackups streams every backup whose refresh timestamps are
// strictly before purgeTime.
func (m *Manager) GetExpiredBackups(
	ctx context.Context,
	segments int,
	purgeTime time.Time,
	fn func(ExpiredBackup) error,
) error {
	return m.store.GetExpiredBackups(ctx, segments, purgeTime, fn)
}

// ExpireBackup deletes the CDN prefix referenced by expired and clears the
// metadata row.
func (m *Manager) ExpireBackup(ctx context.Context, expired ExpiredBackup) error {
	if err := m.store.StartExpiration(ctx, expired); err != nil {
		return err
	}
	if err := m.deletePrefix(ctx, expired.PrefixToDelete); err != nil {
		return err
	}
	return m.store.FinishExpiration(ctx, expired)
}

// RecalculateQuota walks the CDN media prefix and writes the fresh usage
// figure to storage. Returns the before/after values for telemetry.
func (m *Manager) RecalculateQuota(
	ctx context.Context,
	attrs StoredAttributes,
) (*RecalculationResult, error) {
	if attrs.BackupDir == "" || attrs.MediaDir == "" {
		return nil, &InvalidArgumentError{Field: "attrs", Message: "missing backup/media directory"}
	}
	prefix := attrs.BackupDir + "/" + attrs.MediaDir + "/"
	usage, err := m.blob.CalculateBytesUsed(ctx, prefix)
	if err != nil {
		return nil, err
	}
	if err := m.store.SetMediaUsageFor(ctx, attrs, usage); err != nil {
		return nil, err
	}
	return &RecalculationResult{
		OldUsage: UsageInfo{BytesUsed: attrs.BytesUsed, NumObjects: attrs.NumObjects},
		NewUsage: usage,
	}, nil
}

// --- internals --------------------------------------------------------------

// classifyCopyError maps an error returned by [BlobStore.Copy] to the
// per-item outcome the client sees. Unmapped errors propagate up as
// hard failures.
func classifyCopyError(err error) (CopyOutcome, bool) {
	var snf *SourceNotFoundError
	if errors.As(err, &snf) {
		return CopyOutcomeSourceNotFound, true
	}
	var inv *InvalidLengthError
	if errors.As(err, &inv) {
		return CopyOutcomeSourceWrongLength, true
	}
	return 0, false
}

func makeCopyQuota(user AuthenticatedUser, toCopy []CopyParameters, remaining int64) *CopyQuota {
	sum := int64(0)
	idx := len(toCopy)
	for i, p := range toCopy {
		sum += p.DestinationObjectSize()
		if sum > remaining {
			idx = i
			break
		}
	}
	return &CopyQuota{
		User:           user,
		RequestsToCopy: append([]CopyParameters(nil), toCopy[:idx]...),
		ToReject:       append([]CopyParameters(nil), toCopy[idx:]...),
	}
}

// deletePrefix lists every object under prefix and deletes them. Used by
// both DeleteEntireBackup's sync-fallback path and ExpireBackup.
func (m *Manager) deletePrefix(ctx context.Context, prefix string) error {
	if len(prefix) != BackupDirectoryPathLength && len(prefix) != MediaDirectoryPathLength {
		return &InvalidArgumentError{Field: "prefix", Message: "unexpected length"}
	}
	withSlash := prefix + "/"
	var cursor *string
	for {
		page, err := m.blob.List(ctx, withSlash, cursor, 1000)
		if err != nil {
			return err
		}
		for _, obj := range page.Objects {
			if _, err := m.blob.Delete(ctx, withSlash+obj.Key); err != nil {
				return err
			}
		}
		if page.Cursor == nil {
			return nil
		}
		cursor = page.Cursor
	}
}

// cdnMessageBackupName returns "<backupDir>/messageBackup".
func cdnMessageBackupName(user *AuthenticatedUser) string {
	return user.BackupDir + "/" + MessageBackupName
}

// cdnMediaDirectory returns "<backupDir>/<mediaDir>/".
func cdnMediaDirectory(user *AuthenticatedUser) string {
	return user.BackupDir + "/" + user.MediaDir + "/"
}

// cdnMediaPath returns "<backupDir>/<mediaDir>/<base64url(mediaID)>".
func cdnMediaPath(user *AuthenticatedUser, mediaID []byte) string {
	return cdnMediaDirectory(user) + base64.URLEncoding.EncodeToString(mediaID)
}

// decodeMediaIDFromCDN reverses encodeMediaIDForCDN.
func decodeMediaIDFromCDN(s string) ([]byte, error) {
	out, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, &InvalidArgumentError{Field: "cdnKey", Message: "not base64url"}
	}
	return out, nil
}

// requireLevel returns *PermissionError if the user's tier is below required.
func requireLevel(user *AuthenticatedUser, required BackupLevel) error {
	if user == nil {
		return &FailedZkAuthError{Reason: "no authenticated user"}
	}
	if user.BackupLevel < required {
		return &PermissionError{Required: required, Got: user.BackupLevel}
	}
	return nil
}

// requireCredentialType returns *WrongCredentialTypeError if mismatched.
func requireCredentialType(user *AuthenticatedUser, required CredentialType) error {
	if user.CredentialType != required {
		return &WrongCredentialTypeError{Required: required, Got: user.CredentialType}
	}
	return nil
}

// orDefaultInt64 returns v if non-zero, else def.
func orDefaultInt64(v, def int64) int64 {
	if v == 0 {
		return def
	}
	return v
}
