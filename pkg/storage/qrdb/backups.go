package qrdb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/backups"
)

// Compile-time interface satisfaction checks.
var (
	_ backups.Store                 = (*BackupStore)(nil)
	_ backups.RedeemedReceiptsStore = (*RedeemedReceiptsStore)(nil)
)

// Key prefixes used by the backup-related qrdb stores. Pattern matches
// the other domain stores in this package ("signal:<domain>:<id>").
const (
	backupKeyPrefix        = "signal:backup:"
	backupPendingDelPrefix = "signal:backup:pending:"
	redeemedReceiptKeyPref = "signal:backup:receipt:"
)

// backupEntry is the persisted JSON form. The on-disk representation lives
// in this file rather than in pkg/backups/types.go so the wire types do
// not pick up storage-specific tags.
type backupEntry struct {
	HashedBackupID   []byte    `json:"hashedBackupId"`
	PublicKey        []byte    `json:"publicKey"`
	Level            int       `json:"level"`
	BackupDir        string    `json:"backupDir"`
	MediaDir         string    `json:"mediaDir"`
	LastRefresh      time.Time `json:"lastRefresh"`
	LastMediaRefresh time.Time `json:"lastMediaRefresh"`
	BytesUsed        int64     `json:"bytesUsed"`
	NumObjects       int64     `json:"numObjects"`
	UsageRecalcAt    time.Time `json:"usageRecalcAt,omitempty"`
}

// BackupStore is a qrdb-backed implementation of [backups.Store].
type BackupStore struct {
	kv  KVStore
	now func() time.Time
}

// NewBackupStore returns a store that persists to kv.
func NewBackupStore(kv KVStore) *BackupStore {
	return &BackupStore{kv: kv, now: func() time.Time { return time.Now().UTC() }}
}

// SetClock overrides the time source. Intended for tests.
func (s *BackupStore) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func backupKey(id backups.BackupID) string {
	sum := sha256.Sum256(id[:])
	return backupKeyPrefix + hex.EncodeToString(sum[:16])
}

func backupKeyByHash(hashed []byte) string {
	if len(hashed) > 16 {
		hashed = hashed[:16]
	}
	return backupKeyPrefix + hex.EncodeToString(hashed)
}

func pendingKey(hashed []byte, prefix string) string {
	return backupPendingDelPrefix + hex.EncodeToString(hashed) + ":" + prefix
}

func generateDirName() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])[:16]
}

// load fetches and decodes the entry, returning (nil, nil) on miss.
func (s *BackupStore) load(ctx context.Context, key string) (*backupEntry, error) {
	raw, err := s.kv.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	var entry backupEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

func (s *BackupStore) save(ctx context.Context, key string, entry *backupEntry) error {
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return s.kv.Put(ctx, key, raw)
}

// SetPublicKey implements [backups.Store].
func (s *BackupStore) SetPublicKey(
	ctx context.Context,
	id backups.BackupID,
	level backups.BackupLevel,
	publicKey []byte,
) error {
	key := backupKey(id)
	entry, err := s.load(ctx, key)
	if err != nil {
		return err
	}
	now := s.now()
	if entry != nil {
		if subtle.ConstantTimeCompare(entry.PublicKey, publicKey) != 1 {
			return &backups.PublicKeyConflictError{BackupID: id}
		}
		entry.Level = int(level)
		entry.LastRefresh = now
		return s.save(ctx, key, entry)
	}
	sum := sha256.Sum256(id[:])
	entry = &backupEntry{
		HashedBackupID:   append([]byte(nil), sum[:16]...),
		PublicKey:        append([]byte(nil), publicKey...),
		Level:            int(level),
		BackupDir:        generateDirName(),
		MediaDir:         generateDirName(),
		LastRefresh:      now,
		LastMediaRefresh: now,
	}
	return s.save(ctx, key, entry)
}

// RetrieveAuthenticationData implements [backups.Store].
func (s *BackupStore) RetrieveAuthenticationData(
	ctx context.Context,
	id backups.BackupID,
) (*backups.AuthenticationData, bool, error) {
	entry, err := s.load(ctx, backupKey(id))
	if err != nil {
		return nil, false, err
	}
	if entry == nil {
		return nil, false, nil
	}
	return &backups.AuthenticationData{
		PublicKey: append([]byte(nil), entry.PublicKey...),
		BackupDir: entry.BackupDir,
		MediaDir:  entry.MediaDir,
	}, true, nil
}

// AddMessageBackup implements [backups.Store].
func (s *BackupStore) AddMessageBackup(ctx context.Context, user backups.AuthenticatedUser) error {
	key := backupKey(user.BackupID)
	entry, err := s.load(ctx, key)
	if err != nil {
		return err
	}
	if entry == nil {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}
	entry.LastRefresh = s.now()
	return s.save(ctx, key, entry)
}

// TTLRefresh implements [backups.Store].
func (s *BackupStore) TTLRefresh(ctx context.Context, user backups.AuthenticatedUser) (*backups.StoredAttributes, error) {
	key := backupKey(user.BackupID)
	entry, err := s.load(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, &backups.NotFoundError{BackupID: user.BackupID}
	}
	now := s.now()
	entry.LastRefresh = now
	if user.CredentialType == backups.CredentialTypeMedia {
		entry.LastMediaRefresh = now
	}
	if err := s.save(ctx, key, entry); err != nil {
		return nil, err
	}
	return entryToAttributes(entry), nil
}

// DescribeBackup implements [backups.Store].
func (s *BackupStore) DescribeBackup(ctx context.Context, user backups.AuthenticatedUser) (*backups.Description, error) {
	entry, err := s.load(ctx, backupKey(user.BackupID))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, &backups.NotFoundError{BackupID: user.BackupID}
	}
	desc := &backups.Description{CDN: 3}
	if user.CredentialType == backups.CredentialTypeMedia {
		used := entry.BytesUsed
		desc.MediaUsedSpace = &used
	}
	return desc, nil
}

// TrackMedia implements [backups.Store].
func (s *BackupStore) TrackMedia(ctx context.Context, user backups.AuthenticatedUser, countDelta, bytesDelta int64) error {
	key := backupKey(user.BackupID)
	entry, err := s.load(ctx, key)
	if err != nil {
		return err
	}
	if entry == nil {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}
	entry.NumObjects += countDelta
	entry.BytesUsed += bytesDelta
	if entry.NumObjects < 0 {
		entry.NumObjects = 0
	}
	if entry.BytesUsed < 0 {
		entry.BytesUsed = 0
	}
	return s.save(ctx, key, entry)
}

// GetMediaUsage implements [backups.Store].
func (s *BackupStore) GetMediaUsage(ctx context.Context, user backups.AuthenticatedUser) (*backups.TimestampedUsageInfo, error) {
	entry, err := s.load(ctx, backupKey(user.BackupID))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, &backups.NotFoundError{BackupID: user.BackupID}
	}
	return &backups.TimestampedUsageInfo{
		Usage:                 backups.UsageInfo{BytesUsed: entry.BytesUsed, NumObjects: entry.NumObjects},
		LastRecalculationTime: entry.UsageRecalcAt,
	}, nil
}

// SetMediaUsage implements [backups.Store].
func (s *BackupStore) SetMediaUsage(ctx context.Context, user backups.AuthenticatedUser, usage backups.UsageInfo) error {
	key := backupKey(user.BackupID)
	entry, err := s.load(ctx, key)
	if err != nil {
		return err
	}
	if entry == nil {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}
	entry.BytesUsed = usage.BytesUsed
	entry.NumObjects = usage.NumObjects
	entry.UsageRecalcAt = s.now()
	return s.save(ctx, key, entry)
}

// SetMediaUsageFor implements [backups.Store] for the worker path.
func (s *BackupStore) SetMediaUsageFor(ctx context.Context, attrs backups.StoredAttributes, usage backups.UsageInfo) error {
	key := backupKeyByHash(attrs.HashedBackupID)
	entry, err := s.load(ctx, key)
	if err != nil {
		return err
	}
	if entry == nil {
		return &backups.NotFoundError{}
	}
	entry.BytesUsed = usage.BytesUsed
	entry.NumObjects = usage.NumObjects
	entry.UsageRecalcAt = s.now()
	return s.save(ctx, key, entry)
}

// ScheduleBackupDeletion implements [backups.Store]. The old backupDir is
// recorded under the pending-deletion prefix and the entry is reseeded
// with fresh directories.
func (s *BackupStore) ScheduleBackupDeletion(ctx context.Context, user backups.AuthenticatedUser) error {
	key := backupKey(user.BackupID)
	entry, err := s.load(ctx, key)
	if err != nil {
		return err
	}
	if entry == nil {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}

	pk := pendingKey(entry.HashedBackupID, entry.BackupDir)
	exists, err := s.kv.Exists(ctx, pk)
	if err != nil {
		return err
	}
	if exists {
		return &backups.PendingDeletionError{BackupID: user.BackupID}
	}

	pending := backups.ExpiredBackup{
		HashedBackupID: append([]byte(nil), entry.HashedBackupID...),
		ExpirationType: backups.ExpireAll,
		LastRefresh:    entry.LastRefresh,
		PrefixToDelete: entry.BackupDir,
	}
	raw, err := json.Marshal(pending)
	if err != nil {
		return err
	}
	if err := s.kv.Put(ctx, pk, raw); err != nil {
		return err
	}

	entry.BackupDir = generateDirName()
	entry.MediaDir = generateDirName()
	entry.BytesUsed = 0
	entry.NumObjects = 0
	return s.save(ctx, key, entry)
}

// StartExpiration is a no-op for the qrdb backend (no lease semantics).
func (s *BackupStore) StartExpiration(_ context.Context, _ backups.ExpiredBackup) error {
	return nil
}

// FinishExpiration removes the pending-deletion row.
func (s *BackupStore) FinishExpiration(ctx context.Context, expired backups.ExpiredBackup) error {
	return s.kv.Delete(ctx, pendingKey(expired.HashedBackupID, expired.PrefixToDelete))
}

// ListBackupAttributes streams every entry to fn.
func (s *BackupStore) ListBackupAttributes(ctx context.Context, _ int, fn func(backups.StoredAttributes) error) error {
	var cbErr error
	scanErr := s.kv.Scan(ctx, backupKeyPrefix, func(key string, value []byte) error {
		// Skip pending-deletion rows that share the same prefix.
		if len(key) > len(backupPendingDelPrefix) && key[:len(backupPendingDelPrefix)] == backupPendingDelPrefix {
			return nil
		}
		var entry backupEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			return err
		}
		if err := fn(*entryToAttributes(&entry)); err != nil {
			cbErr = err
			return errStopScan
		}
		return nil
	})
	if errors.Is(scanErr, errStopScan) {
		return cbErr
	}
	return scanErr
}

// GetExpiredBackups streams live + pending-deletion rows to fn.
func (s *BackupStore) GetExpiredBackups(
	ctx context.Context,
	_ int,
	purgeTime time.Time,
	fn func(backups.ExpiredBackup) error,
) error {
	// Live rows.
	var cbErr error
	scanErr := s.kv.Scan(ctx, backupKeyPrefix, func(key string, value []byte) error {
		if len(key) > len(backupPendingDelPrefix) && key[:len(backupPendingDelPrefix)] == backupPendingDelPrefix {
			return nil
		}
		var entry backupEntry
		if err := json.Unmarshal(value, &entry); err != nil {
			return err
		}
		if !entry.LastRefresh.Before(purgeTime) {
			return nil
		}
		expType := backups.ExpireMedia
		prefix := entry.BackupDir + "/" + entry.MediaDir
		if entry.LastMediaRefresh.Before(purgeTime) {
			expType = backups.ExpireAll
			prefix = entry.BackupDir
		}
		if err := fn(backups.ExpiredBackup{
			HashedBackupID: append([]byte(nil), entry.HashedBackupID...),
			ExpirationType: expType,
			LastRefresh:    entry.LastRefresh,
			PrefixToDelete: prefix,
		}); err != nil {
			cbErr = err
			return errStopScan
		}
		return nil
	})
	if errors.Is(scanErr, errStopScan) {
		return cbErr
	}
	if scanErr != nil {
		return scanErr
	}
	// Pending-deletion rows (always reported as garbage-collection).
	scanErr = s.kv.Scan(ctx, backupPendingDelPrefix, func(_ string, value []byte) error {
		var pending backups.ExpiredBackup
		if err := json.Unmarshal(value, &pending); err != nil {
			return err
		}
		pending.ExpirationType = backups.ExpireGarbageCollection
		if err := fn(pending); err != nil {
			cbErr = err
			return errStopScan
		}
		return nil
	})
	if errors.Is(scanErr, errStopScan) {
		return cbErr
	}
	return scanErr
}

// errStopScan is the sentinel used to terminate a Scan early once fn errors.
var errStopScan = errors.New("backups: stop scan")

func entryToAttributes(e *backupEntry) *backups.StoredAttributes {
	return &backups.StoredAttributes{
		HashedBackupID:   append([]byte(nil), e.HashedBackupID...),
		BackupDir:        e.BackupDir,
		MediaDir:         e.MediaDir,
		LastRefresh:      e.LastRefresh,
		LastMediaRefresh: e.LastMediaRefresh,
		BytesUsed:        e.BytesUsed,
		NumObjects:       e.NumObjects,
	}
}

// --- RedeemedReceiptsStore --------------------------------------------------

// redeemedReceiptEntry is the persisted JSON form.
type redeemedReceiptEntry struct {
	Expiration   time.Time `json:"expiration"`
	ReceiptLevel uint64    `json:"receiptLevel"`
	AccountUUID  string    `json:"accountUUID"`
}

// RedeemedReceiptsStore is a qrdb-backed implementation of
// [backups.RedeemedReceiptsStore]. Lazy-expires entries on read.
type RedeemedReceiptsStore struct {
	kv  KVStore
	now func() time.Time
}

// NewRedeemedReceiptsStore returns a store that persists to kv.
func NewRedeemedReceiptsStore(kv KVStore) *RedeemedReceiptsStore {
	return &RedeemedReceiptsStore{kv: kv, now: func() time.Time { return time.Now().UTC() }}
}

// SetClock overrides the time source. Intended for tests.
func (s *RedeemedReceiptsStore) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func receiptKey(serial []byte) string {
	return redeemedReceiptKeyPref + hex.EncodeToString(serial)
}

// Put implements [backups.RedeemedReceiptsStore].
func (s *RedeemedReceiptsStore) Put(
	ctx context.Context,
	receiptSerial []byte,
	expiration time.Time,
	receiptLevel uint64,
	accountUUID string,
) (bool, error) {
	key := receiptKey(receiptSerial)
	raw, err := s.kv.Get(ctx, key)
	if err != nil {
		return false, err
	}
	now := s.now()
	if raw != nil {
		var existing redeemedReceiptEntry
		if err := json.Unmarshal(raw, &existing); err != nil {
			return false, err
		}
		if !existing.Expiration.After(now) {
			// Expired entry: lazy-evict and fall through to fresh insert.
			if err := s.kv.Delete(ctx, key); err != nil {
				return false, err
			}
		} else {
			return existing.AccountUUID == accountUUID, nil
		}
	}
	entry := redeemedReceiptEntry{
		Expiration:   expiration,
		ReceiptLevel: receiptLevel,
		AccountUUID:  accountUUID,
	}
	val, err := json.Marshal(entry)
	if err != nil {
		return false, err
	}
	if err := s.kv.Put(ctx, key, val); err != nil {
		return false, err
	}
	return true, nil
}
