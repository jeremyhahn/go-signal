package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/backups"
)

// truncateBackupsTables removes all rows from the backup-related tables so
// each test starts with a clean slate. Called via t.Cleanup in every test.
func truncateBackupsTables(ctx context.Context, c *Client) error {
	const sql = `TRUNCATE TABLE
		backup_redeemed_receipts,
		backups_pending_deletion,
		backups
	RESTART IDENTITY CASCADE`
	_, err := c.pool.Exec(ctx, sql)
	return err
}

// newPgBackupID returns a [backups.BackupID] with every byte set to b.
func newPgBackupID(b byte) backups.BackupID {
	var id backups.BackupID
	for i := range id {
		id[i] = b
	}
	return id
}

// newPgUser constructs a minimal [backups.AuthenticatedUser] for test use.
func newPgUser(id backups.BackupID, ct backups.CredentialType) backups.AuthenticatedUser {
	return backups.AuthenticatedUser{
		BackupID:       id,
		CredentialType: ct,
		BackupLevel:    backups.BackupLevelFree,
		BackupDir:      "dir",
		MediaDir:       "media",
	}
}

// ---- SetPublicKey ------------------------------------------------------------

func TestPostgresBackupStore_SetPublicKey_FirstAndConflict(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	id := newPgBackupID(0xAA)

	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk1")); err != nil {
		t.Fatalf("first SetPublicKey: %v", err)
	}
	// Re-setting with the same key is idempotent.
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk1")); err != nil {
		t.Fatalf("repeat SetPublicKey same key: %v", err)
	}
	// Conflicting key must return *PublicKeyConflictError.
	err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk2"))
	var conflict *backups.PublicKeyConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected *PublicKeyConflictError, got %T: %v", err, err)
	}
}

// ---- RetrieveAuthenticationData ---------------------------------------------

func TestPostgresBackupStore_RetrieveAuthenticationData_HappyAndMissing(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	id := newPgBackupID(0x11)
	pk := []byte("publickey")

	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, pk); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	data, ok, err := s.RetrieveAuthenticationData(ctx, id)
	if err != nil || !ok {
		t.Fatalf("RetrieveAuthenticationData ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(data.PublicKey, pk) {
		t.Errorf("public key mismatch: got %x want %x", data.PublicKey, pk)
	}
	if data.BackupDir == "" || data.MediaDir == "" {
		t.Errorf("backup/media dir not seeded: %+v", data)
	}

	// Missing id → ok=false, no error.
	_, ok, err = s.RetrieveAuthenticationData(ctx, newPgBackupID(0x22))
	if err != nil || ok {
		t.Errorf("missing id should return ok=false, got ok=%v err=%v", ok, err)
	}
}

// ---- TTLRefresh -------------------------------------------------------------

func TestPostgresBackupStore_TTLRefresh_UpdatesTimestamps(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	id := newPgBackupID(0x33)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}

	t0 := time.Now().UTC().Truncate(time.Second)
	s.SetClock(func() time.Time { return t0 })

	msgUser := newPgUser(id, backups.CredentialTypeMessages)
	attrs, err := s.TTLRefresh(ctx, msgUser)
	if err != nil {
		t.Fatalf("TTLRefresh messages: %v", err)
	}
	if !attrs.LastRefresh.UTC().Truncate(time.Second).Equal(t0) {
		t.Errorf("LastRefresh = %v; want %v", attrs.LastRefresh, t0)
	}

	// Media credential bumps LastMediaRefresh.
	t1 := t0.Add(time.Hour)
	s.SetClock(func() time.Time { return t1 })
	mediaUser := newPgUser(id, backups.CredentialTypeMedia)
	attrs, err = s.TTLRefresh(ctx, mediaUser)
	if err != nil {
		t.Fatalf("TTLRefresh media: %v", err)
	}
	if !attrs.LastMediaRefresh.UTC().Truncate(time.Second).Equal(t1) {
		t.Errorf("LastMediaRefresh = %v; want %v", attrs.LastMediaRefresh, t1)
	}

	// Unknown id → NotFoundError.
	_, err = s.TTLRefresh(ctx, newPgUser(newPgBackupID(0x44), backups.CredentialTypeMessages))
	var nf *backups.NotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *NotFoundError on missing id, got %T: %v", err, err)
	}
}

// ---- AddMessageBackup -------------------------------------------------------

func TestPostgresBackupStore_AddMessageBackup_BumpsLastRefresh(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	id := newPgBackupID(0xA1)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}

	t1 := time.Now().UTC().Truncate(time.Second)
	s.SetClock(func() time.Time { return t1 })
	user := newPgUser(id, backups.CredentialTypeMessages)
	if err := s.AddMessageBackup(ctx, user); err != nil {
		t.Fatalf("AddMessageBackup: %v", err)
	}
	attrs, err := s.TTLRefresh(ctx, user)
	if err != nil {
		t.Fatalf("TTLRefresh: %v", err)
	}
	if !attrs.LastRefresh.UTC().Truncate(time.Second).Equal(t1) {
		t.Errorf("LastRefresh after AddMessageBackup = %v; want %v", attrs.LastRefresh, t1)
	}

	// Unknown id → NotFoundError.
	err = s.AddMessageBackup(ctx, newPgUser(newPgBackupID(0xA2), backups.CredentialTypeMessages))
	var nf *backups.NotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *NotFoundError for unknown id, got %T: %v", err, err)
	}
}

// ---- TrackMedia + GetMediaUsage ---------------------------------------------

func TestPostgresBackupStore_TrackMedia_AndUsageRoundTrip(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	id := newPgBackupID(0x55)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	user := newPgUser(id, backups.CredentialTypeMedia)
	user.BackupLevel = backups.BackupLevelPaid

	if err := s.TrackMedia(ctx, user, 3, 100); err != nil {
		t.Fatalf("TrackMedia +: %v", err)
	}
	usage, err := s.GetMediaUsage(ctx, user)
	if err != nil {
		t.Fatalf("GetMediaUsage: %v", err)
	}
	if usage.Usage.BytesUsed != 100 || usage.Usage.NumObjects != 3 {
		t.Errorf("usage = %+v; want bytes=100 count=3", usage.Usage)
	}

	// Negative delta refunds; clamps at zero via GREATEST(…, 0).
	if err := s.TrackMedia(ctx, user, -10, -1000); err != nil {
		t.Fatalf("TrackMedia -: %v", err)
	}
	usage, err = s.GetMediaUsage(ctx, user)
	if err != nil {
		t.Fatalf("GetMediaUsage after refund: %v", err)
	}
	if usage.Usage.BytesUsed != 0 || usage.Usage.NumObjects != 0 {
		t.Errorf("after refund: usage = %+v; want zeros", usage.Usage)
	}
}

// ---- SetMediaUsage ----------------------------------------------------------

func TestPostgresBackupStore_SetMediaUsage_OverwritesAndStampsRecalc(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	id := newPgBackupID(0x56)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	user := newPgUser(id, backups.CredentialTypeMedia)
	user.BackupLevel = backups.BackupLevelPaid

	t0 := time.Now().UTC().Truncate(time.Second)
	s.SetClock(func() time.Time { return t0 })

	if err := s.SetMediaUsage(ctx, user, backups.UsageInfo{BytesUsed: 5000, NumObjects: 50}); err != nil {
		t.Fatalf("SetMediaUsage: %v", err)
	}
	usage, err := s.GetMediaUsage(ctx, user)
	if err != nil {
		t.Fatalf("GetMediaUsage: %v", err)
	}
	if usage.Usage.BytesUsed != 5000 || usage.Usage.NumObjects != 50 {
		t.Errorf("after SetMediaUsage: %+v", usage.Usage)
	}
	if !usage.LastRecalculationTime.UTC().Truncate(time.Second).Equal(t0) {
		t.Errorf("recalc time = %v; want %v", usage.LastRecalculationTime, t0)
	}
}

// ---- SetMediaUsageFor -------------------------------------------------------

func TestPostgresBackupStore_SetMediaUsageFor_WorkerPath(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	id := newPgBackupID(0xA3)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}

	var attrs backups.StoredAttributes
	if err := s.ListBackupAttributes(ctx, 1, func(a backups.StoredAttributes) error {
		attrs = a
		return nil
	}); err != nil {
		t.Fatalf("ListBackupAttributes: %v", err)
	}

	if err := s.SetMediaUsageFor(ctx, attrs, backups.UsageInfo{BytesUsed: 999, NumObjects: 9}); err != nil {
		t.Fatalf("SetMediaUsageFor: %v", err)
	}
	user := newPgUser(id, backups.CredentialTypeMedia)
	user.BackupLevel = backups.BackupLevelPaid
	usage, err := s.GetMediaUsage(ctx, user)
	if err != nil {
		t.Fatalf("GetMediaUsage: %v", err)
	}
	if usage.Usage.BytesUsed != 999 || usage.Usage.NumObjects != 9 {
		t.Errorf("usage after SetMediaUsageFor = %+v", usage.Usage)
	}

	// Bogus hash → NotFoundError.
	bogus := backups.StoredAttributes{HashedBackupID: []byte("nope-not-a-hash")}
	err = s.SetMediaUsageFor(ctx, bogus, backups.UsageInfo{})
	var nf *backups.NotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *NotFoundError on unknown hash, got %T: %v", err, err)
	}
}

// ---- DescribeBackup ---------------------------------------------------------

func TestPostgresBackupStore_DescribeBackup_TypeAware(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	id := newPgBackupID(0x66)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	user := newPgUser(id, backups.CredentialTypeMedia)
	user.BackupLevel = backups.BackupLevelPaid
	if err := s.TrackMedia(ctx, user, 1, 123); err != nil {
		t.Fatalf("TrackMedia: %v", err)
	}

	// Media credential gets a MediaUsedSpace pointer.
	descMedia, err := s.DescribeBackup(ctx, user)
	if err != nil {
		t.Fatalf("DescribeBackup media: %v", err)
	}
	if descMedia.MediaUsedSpace == nil || *descMedia.MediaUsedSpace != 123 {
		t.Errorf("media describe used = %v", descMedia.MediaUsedSpace)
	}

	// Messages credential must not include used space.
	user.CredentialType = backups.CredentialTypeMessages
	descMessages, err := s.DescribeBackup(ctx, user)
	if err != nil {
		t.Fatalf("DescribeBackup messages: %v", err)
	}
	if descMessages.MediaUsedSpace != nil {
		t.Errorf("messages describe should not include media usage")
	}
}

// ---- ScheduleBackupDeletion -------------------------------------------------

func TestPostgresBackupStore_ScheduleDeletion_RotatesDirsAndQueuesPending(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	id := newPgBackupID(0x77)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	data, _, err := s.RetrieveAuthenticationData(ctx, id)
	if err != nil {
		t.Fatalf("RetrieveAuthenticationData: %v", err)
	}
	originalDir := data.BackupDir

	user := newPgUser(id, backups.CredentialTypeMessages)
	user.BackupDir = data.BackupDir
	user.MediaDir = data.MediaDir
	if err := s.ScheduleBackupDeletion(ctx, user); err != nil {
		t.Fatalf("ScheduleBackupDeletion: %v", err)
	}

	dataAfter, _, err := s.RetrieveAuthenticationData(ctx, id)
	if err != nil {
		t.Fatalf("RetrieveAuthenticationData after schedule: %v", err)
	}
	if dataAfter.BackupDir == originalDir {
		t.Error("backupDir should be rotated after schedule")
	}

	// A second schedule against the freshly-rotated dir also succeeds.
	// PendingDeletionError only fires when the stored entry's current
	// backupDir already has a queued pending row; in normal sequential use
	// each call rotates the dir so this cannot happen.
	user.BackupDir = dataAfter.BackupDir
	user.MediaDir = dataAfter.MediaDir
	if err := s.ScheduleBackupDeletion(ctx, user); err != nil {
		t.Fatalf("second ScheduleBackupDeletion (rotated dir): %v", err)
	}

	// The pending row surfaces as ExpireGarbageCollection.
	purge := time.Now().Add(time.Hour)
	var seenGC bool
	if err := s.GetExpiredBackups(ctx, 1, purge, func(e backups.ExpiredBackup) error {
		if e.ExpirationType == backups.ExpireGarbageCollection {
			seenGC = true
		}
		return nil
	}); err != nil {
		t.Fatalf("GetExpiredBackups: %v", err)
	}
	if !seenGC {
		t.Error("expected at least one ExpireGarbageCollection row")
	}
}

// ---- ListBackupAttributes ---------------------------------------------------

func TestPostgresBackupStore_ListBackupAttributes_StreamsAll(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	for i := byte(1); i <= 5; i++ {
		if err := s.SetPublicKey(ctx, newPgBackupID(i), backups.BackupLevelFree, []byte{i}); err != nil {
			t.Fatalf("SetPublicKey %d: %v", i, err)
		}
	}
	var count int
	if err := s.ListBackupAttributes(ctx, 1, func(attrs backups.StoredAttributes) error {
		count++
		if len(attrs.HashedBackupID) != 16 {
			t.Errorf("HashedBackupID len = %d; want 16", len(attrs.HashedBackupID))
		}
		return nil
	}); err != nil {
		t.Fatalf("ListBackupAttributes: %v", err)
	}
	if count != 5 {
		t.Errorf("count = %d; want 5", count)
	}
}

// ---- StartExpiration / FinishExpiration lifecycle ---------------------------

func TestPostgresBackupStore_StartFinishExpiration_PendingLifecycle(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	id := newPgBackupID(0xA4)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	data, _, err := s.RetrieveAuthenticationData(ctx, id)
	if err != nil {
		t.Fatalf("RetrieveAuthenticationData: %v", err)
	}
	user := newPgUser(id, backups.CredentialTypeMessages)
	user.BackupDir = data.BackupDir
	user.MediaDir = data.MediaDir
	if err := s.ScheduleBackupDeletion(ctx, user); err != nil {
		t.Fatalf("ScheduleBackupDeletion: %v", err)
	}

	// Find the pending row.
	var pending backups.ExpiredBackup
	if err := s.GetExpiredBackups(ctx, 1, time.Now().Add(time.Hour), func(e backups.ExpiredBackup) error {
		if e.ExpirationType == backups.ExpireGarbageCollection {
			pending = e
		}
		return nil
	}); err != nil {
		t.Fatalf("GetExpiredBackups: %v", err)
	}
	if len(pending.HashedBackupID) == 0 {
		t.Fatal("no pending-deletion row found")
	}

	// StartExpiration is a no-op for the postgres backend.
	if err := s.StartExpiration(ctx, pending); err != nil {
		t.Errorf("StartExpiration: %v", err)
	}
	// FinishExpiration clears the row.
	if err := s.FinishExpiration(ctx, pending); err != nil {
		t.Errorf("FinishExpiration: %v", err)
	}
	// After finish, no GC rows remain.
	var stillThere bool
	if err := s.GetExpiredBackups(ctx, 1, time.Now().Add(time.Hour), func(e backups.ExpiredBackup) error {
		if e.ExpirationType == backups.ExpireGarbageCollection {
			stillThere = true
		}
		return nil
	}); err != nil {
		t.Fatalf("GetExpiredBackups after finish: %v", err)
	}
	if stillThere {
		t.Error("pending row not cleared by FinishExpiration")
	}
}

// ---- GetExpiredBackups ------------------------------------------------------

func TestPostgresBackupStore_GetExpiredBackups_ReturnsExpiredRows(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewBackupStore(c)
	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return old })
	for _, b := range []byte{0xE1, 0xE2} {
		if err := s.SetPublicKey(ctx, newPgBackupID(b), backups.BackupLevelFree, []byte{b}); err != nil {
			t.Fatalf("SetPublicKey: %v", err)
		}
	}
	fresh := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return fresh })
	if err := s.SetPublicKey(ctx, newPgBackupID(0xE3), backups.BackupLevelFree, []byte{0xE3}); err != nil {
		t.Fatalf("SetPublicKey fresh: %v", err)
	}

	purge := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var count int
	if err := s.GetExpiredBackups(ctx, 1, purge, func(_ backups.ExpiredBackup) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("GetExpiredBackups: %v", err)
	}
	if count != 2 {
		t.Errorf("expired count = %d; want 2", count)
	}
}

// ---- RedeemedReceiptsStore --------------------------------------------------

func TestPostgresRedeemedReceiptsStore_FirstRedemptionIdempotent(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewRedeemedReceiptsStore(c)
	serial := []byte{1, 2, 3, 4}
	exp := time.Now().Add(time.Hour)

	ok, err := s.Put(ctx, serial, exp, 201, "acct-a")
	if err != nil || !ok {
		t.Fatalf("first Put ok=%v err=%v", ok, err)
	}
	// Same account re-redeems: idempotent, accepted (returns true).
	ok, err = s.Put(ctx, serial, exp, 201, "acct-a")
	if err != nil || !ok {
		t.Fatalf("idempotent Put ok=%v err=%v", ok, err)
	}
	// Different account: rejected (returns false).
	ok, err = s.Put(ctx, serial, exp, 201, "acct-b")
	if err != nil || ok {
		t.Fatalf("cross-account Put should reject: ok=%v err=%v", ok, err)
	}
}

func TestPostgresRedeemedReceiptsStore_ExpiredEntryLazyEvicted(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	t.Cleanup(func() { _ = truncateBackupsTables(ctx, c) })

	s := NewRedeemedReceiptsStore(c)
	serial := []byte{9, 9, 9, 9}
	exp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := s.Put(ctx, serial, exp, 201, "acct-a"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Advance the clock past expiration.
	s.SetClock(func() time.Time { return exp.Add(time.Hour) })

	// A different account must now succeed because the prior entry was lazily
	// evicted on read.
	ok, err := s.Put(ctx, serial, time.Now().Add(24*time.Hour), 201, "acct-b")
	if err != nil || !ok {
		t.Fatalf("post-expiration Put: ok=%v err=%v", ok, err)
	}
}
