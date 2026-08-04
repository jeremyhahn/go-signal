package securestorage

import (
	"encoding/hex"
	"strconv"
)

// ManifestNotFoundError indicates that no manifest has been stored for the
// given account.
type ManifestNotFoundError struct {
	AccountUUID string
}

func (e *ManifestNotFoundError) Error() string {
	return "storage manifest not found for account: " + e.AccountUUID
}

// ManifestVersionConflictError indicates that the submitted manifest version
// is not strictly greater than the currently stored version.
type ManifestVersionConflictError struct {
	AccountUUID      string
	StoredVersion    uint64
	SubmittedVersion uint64
}

func (e *ManifestVersionConflictError) Error() string {
	return "storage manifest version conflict for account " + e.AccountUUID +
		": stored " + strconv.FormatUint(e.StoredVersion, 10) +
		", submitted " + strconv.FormatUint(e.SubmittedVersion, 10)
}

// StorageItemNotFoundError indicates that the requested storage item key does
// not exist for the given account.
type StorageItemNotFoundError struct {
	AccountUUID string
	Key         []byte
}

func (e *StorageItemNotFoundError) Error() string {
	return "storage item not found for account " + e.AccountUUID +
		": key " + hex.EncodeToString(e.Key)
}

// InvalidStorageRequestError indicates a malformed storage-service request
// (e.g. a write operation missing its manifest).
type InvalidStorageRequestError struct {
	Reason string
}

func (e *InvalidStorageRequestError) Error() string {
	return "invalid storage request: " + e.Reason
}
