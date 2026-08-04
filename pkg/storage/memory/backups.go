package memory

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/backups"
)

// Compile-time interface satisfaction checks.
var (
	_ backups.Store                 = (*MemoryBackupStore)(nil)
	_ backups.RedeemedReceiptsStore = (*MemoryRedeemedReceiptsStore)(nil)
)

// MemoryBackupStore is an in-memory implementation of [backups.Store]
// used by tests and single-node dev deployments. State is keyed by the
// hashed backup-id (SHA-256-truncated-to-16 of the raw BackupID) to mirror
// the DynamoDB/qrdb/postgres backends.
type MemoryBackupStore struct {
	mu      sync.RWMutex
	entries map[string]*backupEntry // hex(hashedBackupID) → metadata
	expired map[string]backups.ExpiredBackup
	now     func() time.Time
}

type backupEntry struct {
	hashedBackupID   []byte
	publicKey        []byte
	level            backups.BackupLevel
	backupDir        string
	mediaDir         string
	lastRefresh      time.Time
	lastMediaRefresh time.Time
	bytesUsed        int64
	numObjects       int64
	usageRecalcAt    time.Time
}

// NewMemoryBackupStore returns an empty in-memory backup store.
func NewMemoryBackupStore() *MemoryBackupStore {
	return &MemoryBackupStore{
		entries: make(map[string]*backupEntry),
		expired: make(map[string]backups.ExpiredBackup),
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the clock used to stamp timestamps. Intended for tests.
func (s *MemoryBackupStore) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now != nil {
		s.now = now
	}
}

// hashedKey returns hex-encoded SHA-256-truncated-to-16 of id.
func hashedKey(id backups.BackupID) string {
	sum := sha256.Sum256(id[:])
	return hex.EncodeToString(sum[:16])
}

// generateDirName returns a 16-character base64url string used as a fresh
// backupDir / mediaDir prefix. Matches Java BackupsDb.generateDirName.
func generateDirName() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])[:16]
}

// SetPublicKey implements [backups.Store].
func (s *MemoryBackupStore) SetPublicKey(
	_ context.Context,
	id backups.BackupID,
	level backups.BackupLevel,
	publicKey []byte,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashedKey(id)
	now := s.now()
	if existing, ok := s.entries[key]; ok {
		if subtle.ConstantTimeCompare(existing.publicKey, publicKey) != 1 {
			return &backups.PublicKeyConflictError{BackupID: id}
		}
		existing.level = level
		existing.lastRefresh = now
		return nil
	}
	sum := sha256.Sum256(id[:])
	s.entries[key] = &backupEntry{
		hashedBackupID:   append([]byte(nil), sum[:16]...),
		publicKey:        append([]byte(nil), publicKey...),
		level:            level,
		backupDir:        generateDirName(),
		mediaDir:         generateDirName(),
		lastRefresh:      now,
		lastMediaRefresh: now,
	}
	return nil
}

// RetrieveAuthenticationData implements [backups.Store].
func (s *MemoryBackupStore) RetrieveAuthenticationData(
	_ context.Context,
	id backups.BackupID,
) (*backups.AuthenticationData, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[hashedKey(id)]
	if !ok {
		return nil, false, nil
	}
	return &backups.AuthenticationData{
		PublicKey: append([]byte(nil), entry.publicKey...),
		BackupDir: entry.backupDir,
		MediaDir:  entry.mediaDir,
	}, true, nil
}

// AddMessageBackup implements [backups.Store].
func (s *MemoryBackupStore) AddMessageBackup(_ context.Context, user backups.AuthenticatedUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[hashedKey(user.BackupID)]
	if !ok {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}
	entry.lastRefresh = s.now()
	return nil
}

// TTLRefresh implements [backups.Store].
func (s *MemoryBackupStore) TTLRefresh(_ context.Context, user backups.AuthenticatedUser) (*backups.StoredAttributes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[hashedKey(user.BackupID)]
	if !ok {
		return nil, &backups.NotFoundError{BackupID: user.BackupID}
	}
	now := s.now()
	entry.lastRefresh = now
	if user.CredentialType == backups.CredentialTypeMedia {
		entry.lastMediaRefresh = now
	}
	return entryToAttributes(entry), nil
}

// DescribeBackup implements [backups.Store].
func (s *MemoryBackupStore) DescribeBackup(_ context.Context, user backups.AuthenticatedUser) (*backups.Description, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[hashedKey(user.BackupID)]
	if !ok {
		return nil, &backups.NotFoundError{BackupID: user.BackupID}
	}
	desc := &backups.Description{CDN: 3}
	if user.CredentialType == backups.CredentialTypeMedia {
		used := entry.bytesUsed
		desc.MediaUsedSpace = &used
	}
	return desc, nil
}

// TrackMedia implements [backups.Store].
func (s *MemoryBackupStore) TrackMedia(
	_ context.Context,
	user backups.AuthenticatedUser,
	countDelta, bytesDelta int64,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[hashedKey(user.BackupID)]
	if !ok {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}
	entry.numObjects += countDelta
	entry.bytesUsed += bytesDelta
	if entry.numObjects < 0 {
		entry.numObjects = 0
	}
	if entry.bytesUsed < 0 {
		entry.bytesUsed = 0
	}
	return nil
}

// GetMediaUsage implements [backups.Store].
func (s *MemoryBackupStore) GetMediaUsage(_ context.Context, user backups.AuthenticatedUser) (*backups.TimestampedUsageInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[hashedKey(user.BackupID)]
	if !ok {
		return nil, &backups.NotFoundError{BackupID: user.BackupID}
	}
	return &backups.TimestampedUsageInfo{
		Usage:                 backups.UsageInfo{BytesUsed: entry.bytesUsed, NumObjects: entry.numObjects},
		LastRecalculationTime: entry.usageRecalcAt,
	}, nil
}

// SetMediaUsage implements [backups.Store].
func (s *MemoryBackupStore) SetMediaUsage(_ context.Context, user backups.AuthenticatedUser, usage backups.UsageInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[hashedKey(user.BackupID)]
	if !ok {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}
	entry.bytesUsed = usage.BytesUsed
	entry.numObjects = usage.NumObjects
	entry.usageRecalcAt = s.now()
	return nil
}

// SetMediaUsageFor implements [backups.Store].
func (s *MemoryBackupStore) SetMediaUsageFor(_ context.Context, attrs backups.StoredAttributes, usage backups.UsageInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.entries {
		if subtle.ConstantTimeCompare(entry.hashedBackupID, attrs.HashedBackupID) == 1 {
			entry.bytesUsed = usage.BytesUsed
			entry.numObjects = usage.NumObjects
			entry.usageRecalcAt = s.now()
			return nil
		}
	}
	return &backups.NotFoundError{}
}

// ScheduleBackupDeletion implements [backups.Store]. The old dirs are
// queued in s.expired (ExpirationType=ALL) and the entry is reseeded with
// fresh directories.
func (s *MemoryBackupStore) ScheduleBackupDeletion(_ context.Context, user backups.AuthenticatedUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashedKey(user.BackupID)
	entry, ok := s.entries[key]
	if !ok {
		return &backups.NotFoundError{BackupID: user.BackupID}
	}
	expiredKey := key + ":" + entry.backupDir
	if _, alreadyPending := s.expired[expiredKey]; alreadyPending {
		return &backups.PendingDeletionError{BackupID: user.BackupID}
	}
	s.expired[expiredKey] = backups.ExpiredBackup{
		HashedBackupID: append([]byte(nil), entry.hashedBackupID...),
		ExpirationType: backups.ExpireAll,
		LastRefresh:    entry.lastRefresh,
		PrefixToDelete: entry.backupDir,
	}
	entry.backupDir = generateDirName()
	entry.mediaDir = generateDirName()
	entry.bytesUsed = 0
	entry.numObjects = 0
	return nil
}

// StartExpiration is a no-op for the memory backend (no lease semantics).
func (s *MemoryBackupStore) StartExpiration(_ context.Context, _ backups.ExpiredBackup) error {
	return nil
}

// FinishExpiration removes the pending-expiration row.
func (s *MemoryBackupStore) FinishExpiration(_ context.Context, expired backups.ExpiredBackup) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.expired {
		if subtle.ConstantTimeCompare(v.HashedBackupID, expired.HashedBackupID) == 1 &&
			v.PrefixToDelete == expired.PrefixToDelete {
			delete(s.expired, k)
			return nil
		}
	}
	return nil
}

// ListBackupAttributes streams every row to fn.
func (s *MemoryBackupStore) ListBackupAttributes(_ context.Context, _ int, fn func(backups.StoredAttributes) error) error {
	s.mu.RLock()
	snap := make([]*backupEntry, 0, len(s.entries))
	for _, e := range s.entries {
		snap = append(snap, e)
	}
	s.mu.RUnlock()
	for _, e := range snap {
		if err := fn(*entryToAttributes(e)); err != nil {
			return err
		}
	}
	return nil
}

// GetExpiredBackups streams every row whose lastRefresh < purgeTime to fn.
// A row whose lastMediaRefresh is also < purgeTime is reported as
// ExpireAll; otherwise as ExpireMedia. Pending-deletion rows are emitted
// as ExpireGarbageCollection.
func (s *MemoryBackupStore) GetExpiredBackups(
	_ context.Context,
	_ int,
	purgeTime time.Time,
	fn func(backups.ExpiredBackup) error,
) error {
	s.mu.RLock()
	type pendingRow struct {
		entry *backupEntry
	}
	live := make([]pendingRow, 0, len(s.entries))
	for _, e := range s.entries {
		if e.lastRefresh.Before(purgeTime) {
			live = append(live, pendingRow{e})
		}
	}
	gc := make([]backups.ExpiredBackup, 0, len(s.expired))
	for _, v := range s.expired {
		gc = append(gc, v)
	}
	s.mu.RUnlock()

	for _, row := range live {
		expType := backups.ExpireMedia
		prefix := row.entry.backupDir + "/" + row.entry.mediaDir
		if row.entry.lastMediaRefresh.Before(purgeTime) {
			expType = backups.ExpireAll
			prefix = row.entry.backupDir
		}
		if err := fn(backups.ExpiredBackup{
			HashedBackupID: append([]byte(nil), row.entry.hashedBackupID...),
			ExpirationType: expType,
			LastRefresh:    row.entry.lastRefresh,
			PrefixToDelete: prefix,
		}); err != nil {
			return err
		}
	}
	for _, v := range gc {
		v.ExpirationType = backups.ExpireGarbageCollection
		if err := fn(v); err != nil {
			return err
		}
	}
	return nil
}

// entryToAttributes converts an internal entry to a public StoredAttributes.
func entryToAttributes(e *backupEntry) *backups.StoredAttributes {
	return &backups.StoredAttributes{
		HashedBackupID:   append([]byte(nil), e.hashedBackupID...),
		BackupDir:        e.backupDir,
		MediaDir:         e.mediaDir,
		LastRefresh:      e.lastRefresh,
		LastMediaRefresh: e.lastMediaRefresh,
		BytesUsed:        e.bytesUsed,
		NumObjects:       e.numObjects,
	}
}

// --- RedeemedReceiptsStore --------------------------------------------------

// MemoryRedeemedReceiptsStore tracks redeemed receipt serials in memory.
// Lazy-expires entries on read against an injectable clock.
type MemoryRedeemedReceiptsStore struct {
	mu      sync.Mutex
	entries map[string]redeemedReceiptEntry // hex(serial) → entry
	now     func() time.Time
}

type redeemedReceiptEntry struct {
	expiration   time.Time
	receiptLevel uint64
	accountUUID  string
}

// NewMemoryRedeemedReceiptsStore creates an empty store.
func NewMemoryRedeemedReceiptsStore() *MemoryRedeemedReceiptsStore {
	return &MemoryRedeemedReceiptsStore{
		entries: make(map[string]redeemedReceiptEntry),
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the clock used for expiry checks. Intended for tests.
func (s *MemoryRedeemedReceiptsStore) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now != nil {
		s.now = now
	}
}

// Put records the receipt as redeemed. Returns true on first redemption,
// false if the serial was already recorded by any account before expiry.
// Re-redemption by the same account is idempotent (returns true).
func (s *MemoryRedeemedReceiptsStore) Put(
	_ context.Context,
	receiptSerial []byte,
	expiration time.Time,
	receiptLevel uint64,
	accountUUID string,
) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hex.EncodeToString(receiptSerial)
	now := s.now()
	if existing, ok := s.entries[key]; ok {
		if !existing.expiration.After(now) {
			// Lazy-expire and treat as not present.
			delete(s.entries, key)
		} else {
			// Idempotent re-redemption by the same account is accepted;
			// any other account is rejected.
			return existing.accountUUID == accountUUID, nil
		}
	}
	s.entries[key] = redeemedReceiptEntry{
		expiration:   expiration,
		receiptLevel: receiptLevel,
		accountUUID:  accountUUID,
	}
	return true, nil
}
