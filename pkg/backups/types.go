// Package backups implements the message-archive (backup) subsystem.
//
// It mirrors Java Signal-Server's BackupManager / BackupAuthManager /
// BackupsDb / RemoteStorageManager triad. Storage state lives behind
// the [Store] interface (implemented per-backend under pkg/storage/);
// CDN content lives behind the [BlobStore] interface.
package backups

import (
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// BackupID is the 16-byte backup identifier carried by every backup-auth
// credential. Aliased from go-libsignal's zkgroup so wire-format constants
// stay in one place.
type BackupID = zkgroup.BackupID

// BackupLevel identifies the tier (free or paid).
type BackupLevel = zkgroup.BackupLevel

// CredentialType identifies whether a credential authorizes the messages
// or media backup-id slot.
type CredentialType = zkgroup.BackupCredentialType

const (
	// BackupLevelFree is the free tier (messages only, no paid media quota).
	BackupLevelFree = zkgroup.BackupLevelFree
	// BackupLevelPaid is the paid tier.
	BackupLevelPaid = zkgroup.BackupLevelPaid
)

const (
	// CredentialTypeMessages authorizes the messages backup-id slot.
	CredentialTypeMessages = zkgroup.BackupCredentialTypeMessages
	// CredentialTypeMedia authorizes the media backup-id slot.
	CredentialTypeMedia = zkgroup.BackupCredentialTypeMedia
)

// Object-size limits (mirror Java BackupManager.MAX_MESSAGE_BACKUP_OBJECT_SIZE
// and MAX_MEDIA_OBJECT_SIZE — 101 MiB each).
const (
	MaxMessageBackupObjectSize int64 = 101 * 1024 * 1024
	MaxMediaObjectSize         int64 = 101 * 1024 * 1024
)

// MessageBackupName is the fixed CDN object name for a message-backup blob
// within its backupDir prefix. Matches Java's BackupManager.MESSAGE_BACKUP_NAME.
const MessageBackupName = "messageBackup"

// AuthenticatedUser is an already-authenticated backup user. Produced by
// [Service.AuthenticateBackupUser] after a ZK-credential presentation +
// XEd25519 signature have been verified against the stored public key.
type AuthenticatedUser struct {
	BackupID       BackupID
	CredentialType CredentialType
	BackupLevel    BackupLevel
	BackupDir      string
	MediaDir       string
	UserAgent      string
}

// StoredAttributes is the row stored in the backups table. Mirrors Java's
// StoredBackupAttributes record.
type StoredAttributes struct {
	HashedBackupID   []byte
	BackupDir        string
	MediaDir         string
	LastRefresh      time.Time
	LastMediaRefresh time.Time
	BytesUsed        int64
	NumObjects       int64
}

// AuthenticationData is the subset of [StoredAttributes] needed to verify a
// presentation's signature: the registered public key plus the per-user
// CDN directories.
type AuthenticationData struct {
	PublicKey []byte
	BackupDir string
	MediaDir  string
}

// Description is what [Service.BackupInfo] returns to clients after lookup.
type Description struct {
	CDN            int
	MediaUsedSpace *int64
}

// Info is the assembled response to GET /v1/archives. Combines the static
// per-user CDN paths from the authenticated user with the dynamic
// [Description] from storage.
type Info struct {
	CDN              int
	BackupDir        string
	MediaDir         string
	MessageBackupKey string
	MediaUsedSpace   *int64
}

// UploadDescriptor is a single resumable-upload form. Mirrors Java's
// BackupUploadDescriptor record.
type UploadDescriptor struct {
	CDN                  int
	Key                  string
	Headers              map[string]string
	SignedUploadLocation string
}

// MediaEncryptionParameters carries the AES-256-CBC + HMAC-SHA256 keys used
// to re-encrypt media on copy-to-backup.
type MediaEncryptionParameters struct {
	EncryptionKey []byte
	MACKey        []byte
}

// OutputSize returns the length of a copy destination after re-encryption.
// Matches Java's MediaEncryptionParameters.outputSize: 16-byte IV +
// AES-256-CBC ciphertext (PKCS#7-padded) + 32-byte HMAC tag.
func (p MediaEncryptionParameters) OutputSize(inputSize int) int64 {
	numBlocks := int64((inputSize + 16) / 16)
	return 16 + (numBlocks * 16) + 32
}

// CopyParameters describes a single copy-and-re-encrypt request.
type CopyParameters struct {
	SourceCDN            int
	SourceKey            string
	SourceLength         int
	EncryptionParameters MediaEncryptionParameters
	DestinationMediaID   []byte
}

// DestinationObjectSize returns the size the source will occupy after copy.
func (p CopyParameters) DestinationObjectSize() int64 {
	return p.EncryptionParameters.OutputSize(p.SourceLength)
}

// CopyOutcome enumerates the per-item result of a [Service.CopyToBackup] call.
type CopyOutcome uint8

const (
	// CopyOutcomeSuccess means the object was copied to the backup CDN.
	CopyOutcomeSuccess CopyOutcome = iota
	// CopyOutcomeSourceNotFound means the source object did not exist.
	CopyOutcomeSourceNotFound
	// CopyOutcomeSourceWrongLength means the source object's length did not
	// match the supplied SourceLength.
	CopyOutcomeSourceWrongLength
	// CopyOutcomeOutOfQuota means the destination would exceed the user's
	// remaining media quota.
	CopyOutcomeOutOfQuota
)

// CopyResult is the per-item result of [Service.CopyToBackup]. CDN is set
// only on success.
type CopyResult struct {
	Outcome CopyOutcome
	MediaID []byte
	CDN     *int
}

// CopyQuota splits a batch of copy requests into those that fit in the
// remaining quota and those that should be rejected with [CopyOutcomeOutOfQuota].
type CopyQuota struct {
	User           AuthenticatedUser
	RequestsToCopy []CopyParameters
	ToReject       []CopyParameters
}

// StorageDescriptor identifies a single stored media object.
type StorageDescriptor struct {
	CDN int
	Key []byte
}

// StorageDescriptorWithLength is a [StorageDescriptor] annotated with the
// blob's stored byte length.
type StorageDescriptorWithLength struct {
	CDN    int
	Key    []byte
	Length int64
}

// ListMediaResult is a page of [StorageDescriptorWithLength]. Cursor is nil
// when iteration is complete.
type ListMediaResult struct {
	Media  []StorageDescriptorWithLength
	Cursor *string
}

// BlobListEntry is a single item returned by [BlobStore.List].
type BlobListEntry struct {
	Key    string
	Length int64
}

// BlobListResult is a page of [BlobListEntry]. Cursor is nil when iteration
// is complete.
type BlobListResult struct {
	Objects []BlobListEntry
	Cursor  *string
}

// UsageInfo is a per-backup media usage snapshot.
type UsageInfo struct {
	BytesUsed  int64
	NumObjects int64
}

// TimestampedUsageInfo carries a [UsageInfo] plus the wall-clock time at
// which it was last recalculated. Used by quota enforcement to decide
// whether to trust a cached usage figure or re-list the CDN.
type TimestampedUsageInfo struct {
	Usage                 UsageInfo
	LastRecalculationTime time.Time
}

// ExpirationType classifies an [ExpiredBackup] entry.
type ExpirationType uint8

const (
	// ExpireAll means the entire backup (messages + media) is expired and
	// should be removed wholesale.
	ExpireAll ExpirationType = iota
	// ExpireMedia means the message-backup tier is still active but the
	// media quota has lapsed; only the mediaDir prefix is removed.
	ExpireMedia
	// ExpireGarbageCollection means the prefix is left over from a prior
	// deletion attempt that failed mid-way through.
	ExpireGarbageCollection
)

// ExpiredBackup is a single record returned by [Service.GetExpiredBackups].
// PrefixToDelete is the CDN prefix the worker must purge before clearing
// the metadata row.
type ExpiredBackup struct {
	HashedBackupID []byte
	ExpirationType ExpirationType
	LastRefresh    time.Time
	PrefixToDelete string
}

// RecalculationResult records the before/after usage figures produced by
// [Service.RecalculateQuota]. Used by the backup-usage-recalculation worker
// to emit drift metrics.
type RecalculationResult struct {
	OldUsage UsageInfo
	NewUsage UsageInfo
}

// ExternalServiceCredentials is the username/password pair returned by
// [Service.GenerateSVRBAuth] for clients to authenticate against the SVRB
// service. Mirrors Java's auth.ExternalServiceCredentials record.
//
// Password is a bearer credential, so it is held in protected memory from
// issuance until a handler serialises it onto the response. Handlers read it
// with Password.Reveal() at that single boundary — an unavailable credential
// is an error, not an empty password — and Destroy the credential
// afterwards.
type ExternalServiceCredentials struct {
	Username string
	Password *secrets.SecureString
}

// Destroy wipes the protected password. Safe on nil and idempotent.
func (c *ExternalServiceCredentials) Destroy() {
	if c == nil {
		return
	}
	c.Password.Destroy()
}

// CDN path lengths used to validate prefixes given to [BlobStore.Delete] /
// [Service.ExpireBackup]. Per Java BackupsDb these are the lengths of the
// random base64 strings stored in the backupDir / mediaDir columns.
const (
	BackupDirectoryPathLength = 16
	MediaDirectoryPathLength  = 16
)

// SetBackupIDRequest carries the blinded backup-id commitments uploaded on
// PUT /v1/archives/backupid. Either or both may be empty in a partial
// rotation; at least one must be present.
type SetBackupIDRequest struct {
	MessagesBackupAuthCredentialRequest []byte
	MediaBackupAuthCredentialRequest    []byte
}

// BackupIDLimits reports the cooldown status for backup-id rotation.
// Returned by GET /v1/archives/backupid/limits.
type BackupIDLimits struct {
	// MessagesNextRotationAllowedAt is zero if rotation is allowed now.
	MessagesNextRotationAllowedAt time.Time
	// MediaNextRotationAllowedAt is zero if rotation is allowed now.
	MediaNextRotationAllowedAt time.Time
}

// IssuedCredential is a single day's backup-auth credential response issued
// by GET /v1/archives/auth.
type IssuedCredential struct {
	Type           CredentialType
	RedemptionTime time.Time
	Credential     []byte
}

// CredentialsResponse is the full window of [IssuedCredential]s returned by
// GET /v1/archives/auth — typically up to 7 days for each credential type.
type CredentialsResponse struct {
	Credentials []IssuedCredential
}

// RedeemReceiptRequest carries the serialized receipt presentation uploaded
// on POST /v1/archives/redeem-receipt.
type RedeemReceiptRequest struct {
	ReceiptCredentialPresentation []byte
}
