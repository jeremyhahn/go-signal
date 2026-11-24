package backups

import (
	"encoding/hex"
	"strconv"
)

// PermissionError indicates the authenticated user's credential tier does
// not authorize the requested operation. Translates to HTTP 403 / gRPC
// PERMISSION_DENIED. Mirrors Java's BackupPermissionException.
type PermissionError struct {
	Required BackupLevel
	Got      BackupLevel
}

func (e *PermissionError) Error() string {
	return "backup credential level " + strconv.Itoa(int(e.Got)) +
		" does not authorize operation requiring level " + strconv.Itoa(int(e.Required))
}

// WrongCredentialTypeError indicates the operation requires a different
// credential type (messages vs media) than the one presented. Translates to
// HTTP 401 in Java; we mirror that for parity.
type WrongCredentialTypeError struct {
	Required CredentialType
	Got      CredentialType
}

func (e *WrongCredentialTypeError) Error() string {
	return "backup credential type " + strconv.Itoa(int(e.Got)) +
		" cannot be used for operation requiring type " + strconv.Itoa(int(e.Required))
}

// FailedZkAuthError indicates the ZK presentation or its XEd25519 signature
// failed to verify. Translates to HTTP 401.
type FailedZkAuthError struct {
	Reason string
}

func (e *FailedZkAuthError) Error() string {
	return "backup auth credential verification failed: " + e.Reason
}

// PublicKeyConflictError is returned by [Store.SetPublicKey] when the
// backup-id already has a different public key registered. Translates to
// HTTP 409.
type PublicKeyConflictError struct {
	BackupID BackupID
}

func (e *PublicKeyConflictError) Error() string {
	return "backup public key conflict for id " + hex.EncodeToString(e.BackupID[:])
}

// NotFoundError indicates a record was not found. Translates to HTTP 404.
type NotFoundError struct {
	BackupID BackupID
}

func (e *NotFoundError) Error() string {
	return "backup not found for id " + hex.EncodeToString(e.BackupID[:])
}

// InvalidArgumentError indicates a request argument failed validation.
// Translates to HTTP 400.
type InvalidArgumentError struct {
	Field   string
	Message string
}

func (e *InvalidArgumentError) Error() string {
	return "invalid argument " + e.Field + ": " + e.Message
}

// RateLimitedError is returned when a per-user rate-limit is exceeded.
// Translates to HTTP 429.
type RateLimitedError struct {
	Limit      string
	RetryAfter int64
}

func (e *RateLimitedError) Error() string {
	return "rate limit exceeded: " + e.Limit
}

// SourceNotFoundError is returned by [BlobStore.Copy] when the source CDN
// object cannot be located. Surfaced as [CopyOutcomeSourceNotFound] by the
// [Service.CopyToBackup] aggregation.
type SourceNotFoundError struct {
	SourceKey string
}

func (e *SourceNotFoundError) Error() string {
	return "source object not found: " + e.SourceKey
}

// InvalidLengthError is returned by [BlobStore.Copy] when the source CDN
// object's length does not match the supplied SourceLength. Surfaced as
// [CopyOutcomeSourceWrongLength].
type InvalidLengthError struct {
	SourceKey string
	Expected  int
	Actual    int64
}

func (e *InvalidLengthError) Error() string {
	return "source length mismatch for " + e.SourceKey
}

// BadReceiptError is returned by [AuthManager.RedeemReceipt] when the
// receipt presentation fails verification, is already expired, or has
// already been redeemed. Translates to HTTP 400 Bad Request.
type BadReceiptError struct {
	Reason string
}

func (e *BadReceiptError) Error() string {
	return "bad backup receipt: " + e.Reason
}

// MissingIDCommitmentError is returned by [AuthManager.RedeemReceipt] when
// the account has no committed media credential request — the receipt
// cannot be redeemed because there is no media backup-id to apply it to.
// Translates to HTTP 409.
type MissingIDCommitmentError struct{}

func (e *MissingIDCommitmentError) Error() string {
	return "no media credential request has been committed for the account"
}

// PendingDeletionError is returned by [Store.ScheduleBackupDeletion] when
// the backup already has a pending-deletion swap queued. The caller should
// fall back to a synchronous delete of the existing prefix.
type PendingDeletionError struct {
	BackupID BackupID
}

func (e *PendingDeletionError) Error() string {
	return "backup deletion already pending for id " + hex.EncodeToString(e.BackupID[:])
}
