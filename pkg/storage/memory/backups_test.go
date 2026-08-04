package memory

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/backups"
)

func newBackupID(b byte) backups.BackupID {
	var id backups.BackupID
	for i := range id {
		id[i] = b
	}
	return id
}

func newUser(id backups.BackupID, ct backups.CredentialType) backups.AuthenticatedUser {
	return backups.AuthenticatedUser{
		BackupID:       id,
		CredentialType: ct,
		BackupLevel:    backups.BackupLevelFree,
		BackupDir:      "dir",
		MediaDir:       "media",
	}
}

func TestMemoryBackupStore_SetPublicKey_FirstAndConflict(t *testing.T) {
	s := NewMemoryBackupStore()
	ctx := context.Background()
	id := newBackupID(0xAA)

	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk1")); err != nil {
		t.Fatalf("first SetPublicKey: %v", err)
	}
	// Re-setting with the same key is idempotent.
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk1")); err != nil {
		t.Fatalf("repeat SetPublicKey: %v", err)
	}
	// Conflicting key returns PublicKeyConflictError.
	err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk2"))
	var conflict *backups.PublicKeyConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("expected *PublicKeyConflictError, got %T: %v", err, err)
	}
}

func TestMemoryBackupStore_RetrieveAuthenticationData(t *testing.T) {
	s := NewMemoryBackupStore()
	ctx := context.Background()
	id := newBackupID(0x11)
	pk := []byte("publickey")
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, pk); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	data, ok, err := s.RetrieveAuthenticationData(ctx, id)
	if err != nil || !ok {
		t.Fatalf("RetrieveAuthenticationData ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(data.PublicKey, pk) {
		t.Errorf("public key mismatch")
	}
	if data.BackupDir == "" || data.MediaDir == "" {
		t.Errorf("backup/media dir not seeded")
	}

	// Missing id → ok=false, no error.
	if _, ok, err := s.RetrieveAuthenticationData(ctx, newBackupID(0x22)); err != nil || ok {
		t.Errorf("missing id should return ok=false, got ok=%v err=%v", ok, err)
	}
}

func TestMemoryBackupStore_TTLRefresh_UpdatesTimestamps(t *testing.T) {
	s := NewMemoryBackupStore()
	ctx := context.Background()
	id := newBackupID(0x33)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}

	// Inject a fixed clock so we can observe the update without sleeping.
	t0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return t0 })

	msgUser := newUser(id, backups.CredentialTypeMessages)
	attrs, err := s.TTLRefresh(ctx, msgUser)
	if err != nil {
		t.Fatalf("TTLRefresh: %v", err)
	}
	if !attrs.LastRefresh.Equal(t0) {
		t.Errorf("LastRefresh = %v; want %v", attrs.LastRefresh, t0)
	}

	// Media credential should bump LastMediaRefresh too.
	t1 := t0.Add(time.Hour)
	s.SetClock(func() time.Time { return t1 })
	mediaUser := newUser(id, backups.CredentialTypeMedia)
	attrs, err = s.TTLRefresh(ctx, mediaUser)
	if err != nil {
		t.Fatalf("TTLRefresh media: %v", err)
	}
	if !attrs.LastMediaRefresh.Equal(t1) {
		t.Errorf("LastMediaRefresh = %v; want %v", attrs.LastMediaRefresh, t1)
	}

	// Unknown id → NotFoundError.
	if _, err := s.TTLRefresh(ctx, newUser(newBackupID(0x44), backups.CredentialTypeMessages)); err == nil {
		t.Error("TTLRefresh on missing id should error")
	}
}

func TestMemoryBackupStore_TrackMedia_AndUsageRoundTrip(t *testing.T) {
	s := NewMemoryBackupStore()
	ctx := context.Background()
	id := newBackupID(0x55)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	user := newUser(id, backups.CredentialTypeMedia)
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

	// Refund clamps at zero — never goes negative.
	if err := s.TrackMedia(ctx, user, -10, -1000); err != nil {
		t.Fatalf("TrackMedia -: %v", err)
	}
	usage, _ = s.GetMediaUsage(ctx, user)
	if usage.Usage.BytesUsed != 0 || usage.Usage.NumObjects != 0 {
		t.Errorf("after refund: usage = %+v; want zeros", usage.Usage)
	}

	// SetMediaUsage overwrites + stamps recalc time.
	t0 := time.Now().UTC().Truncate(time.Second)
	s.SetClock(func() time.Time { return t0 })
	if err := s.SetMediaUsage(ctx, user, backups.UsageInfo{BytesUsed: 5000, NumObjects: 50}); err != nil {
		t.Fatalf("SetMediaUsage: %v", err)
	}
	usage, _ = s.GetMediaUsage(ctx, user)
	if usage.Usage.BytesUsed != 5000 || usage.Usage.NumObjects != 50 {
		t.Errorf("after SetMediaUsage: %+v", usage.Usage)
	}
	if !usage.LastRecalculationTime.Equal(t0) {
		t.Errorf("recalc time = %v; want %v", usage.LastRecalculationTime, t0)
	}
}

func TestMemoryBackupStore_DescribeBackup_TypeAware(t *testing.T) {
	s := NewMemoryBackupStore()
	ctx := context.Background()
	id := newBackupID(0x66)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk"))
	user := newUser(id, backups.CredentialTypeMedia)
	user.BackupLevel = backups.BackupLevelPaid
	_ = s.TrackMedia(ctx, user, 1, 123)

	// Media credential gets a MediaUsedSpace pointer.
	descMedia, _ := s.DescribeBackup(ctx, user)
	if descMedia.MediaUsedSpace == nil || *descMedia.MediaUsedSpace != 123 {
		t.Errorf("media describe used = %v", descMedia.MediaUsedSpace)
	}

	// Messages credential does not include used space.
	user.CredentialType = backups.CredentialTypeMessages
	descMessages, _ := s.DescribeBackup(ctx, user)
	if descMessages.MediaUsedSpace != nil {
		t.Errorf("messages describe should not include media usage")
	}
}

func TestMemoryBackupStore_ScheduleDeletion_RotatesDirsAndQueuesPrefix(t *testing.T) {
	s := NewMemoryBackupStore()
	ctx := context.Background()
	id := newBackupID(0x77)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk"))
	data, _, _ := s.RetrieveAuthenticationData(ctx, id)
	originalDir := data.BackupDir

	user := newUser(id, backups.CredentialTypeMessages)
	user.BackupDir = data.BackupDir
	user.MediaDir = data.MediaDir
	if err := s.ScheduleBackupDeletion(ctx, user); err != nil {
		t.Fatalf("ScheduleBackupDeletion: %v", err)
	}
	dataAfter, _, _ := s.RetrieveAuthenticationData(ctx, id)
	if dataAfter.BackupDir == originalDir {
		t.Error("backupDir should be rotated after schedule")
	}

	// A second schedule against the rotated dir is fine; against the
	// same already-pending dir errors with PendingDeletionError.
	user.BackupDir = dataAfter.BackupDir
	user.MediaDir = dataAfter.MediaDir
	if err := s.ScheduleBackupDeletion(ctx, user); err != nil {
		t.Fatalf("second ScheduleBackupDeletion (rotated dir): %v", err)
	}

	// Pending row should surface as garbage-collection in GetExpiredBackups.
	purge := time.Now().Add(time.Hour)
	var seenGC bool
	_ = s.GetExpiredBackups(ctx, 1, purge, func(e backups.ExpiredBackup) error {
		if e.ExpirationType == backups.ExpireGarbageCollection {
			seenGC = true
		}
		return nil
	})
	if !seenGC {
		t.Error("expected at least one ExpireGarbageCollection row in GetExpiredBackups")
	}
}

func TestMemoryBackupStore_ListBackupAttributes_StreamsAll(t *testing.T) {
	s := NewMemoryBackupStore()
	ctx := context.Background()
	for i := byte(1); i <= 5; i++ {
		_ = s.SetPublicKey(ctx, newBackupID(i), backups.BackupLevelFree, []byte{i})
	}
	var count int
	err := s.ListBackupAttributes(ctx, 1, func(attrs backups.StoredAttributes) error {
		count++
		if len(attrs.HashedBackupID) != 16 {
			t.Errorf("HashedBackupID len = %d; want 16", len(attrs.HashedBackupID))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ListBackupAttributes: %v", err)
	}
	if count != 5 {
		t.Errorf("count = %d; want 5", count)
	}
}

func TestMemoryBackupStore_AddMessageBackup_BumpsLastRefresh(t *testing.T) {
	s := NewMemoryBackupStore()
	ctx := context.Background()
	id := newBackupID(0xA1)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk"))
	t1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return t1 })
	user := newUser(id, backups.CredentialTypeMessages)
	if err := s.AddMessageBackup(ctx, user); err != nil {
		t.Fatalf("AddMessageBackup: %v", err)
	}
	attrs, _ := s.TTLRefresh(ctx, user) // ttl refresh returns current attrs
	if !attrs.LastRefresh.Equal(t1) {
		t.Errorf("LastRefresh after add = %v; want %v", attrs.LastRefresh, t1)
	}

	// Missing id errors.
	if err := s.AddMessageBackup(ctx, newUser(newBackupID(0xA2), backups.CredentialTypeMessages)); err == nil {
		t.Error("expected error for unknown id")
	}
}

func TestMemoryBackupStore_SetMediaUsageFor_WorkerPath(t *testing.T) {
	s := NewMemoryBackupStore()
	ctx := context.Background()
	id := newBackupID(0xA3)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk"))

	var attrs backups.StoredAttributes
	_ = s.ListBackupAttributes(ctx, 1, func(a backups.StoredAttributes) error {
		attrs = a
		return nil
	})
	if err := s.SetMediaUsageFor(ctx, attrs, backups.UsageInfo{BytesUsed: 999, NumObjects: 9}); err != nil {
		t.Fatalf("SetMediaUsageFor: %v", err)
	}
	user := newUser(id, backups.CredentialTypeMedia)
	user.BackupLevel = backups.BackupLevelPaid
	usage, _ := s.GetMediaUsage(ctx, user)
	if usage.Usage.BytesUsed != 999 || usage.Usage.NumObjects != 9 {
		t.Errorf("usage after SetMediaUsageFor = %+v", usage.Usage)
	}

	// Bogus hash → NotFoundError.
	bogus := backups.StoredAttributes{HashedBackupID: []byte("nope-not-a-hash")}
	if err := s.SetMediaUsageFor(ctx, bogus, backups.UsageInfo{}); err == nil {
		t.Error("expected NotFoundError on unknown hash")
	}
}

func TestMemoryBackupStore_StartFinishExpiration_PendingLifecycle(t *testing.T) {
	s := NewMemoryBackupStore()
	ctx := context.Background()
	id := newBackupID(0xA4)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk"))
	user := newUser(id, backups.CredentialTypeMessages)
	data, _, _ := s.RetrieveAuthenticationData(ctx, id)
	user.BackupDir = data.BackupDir
	user.MediaDir = data.MediaDir
	if err := s.ScheduleBackupDeletion(ctx, user); err != nil {
		t.Fatalf("ScheduleBackupDeletion: %v", err)
	}

	// Locate the pending row via GetExpiredBackups.
	var pending backups.ExpiredBackup
	_ = s.GetExpiredBackups(ctx, 1, time.Now().Add(time.Hour), func(e backups.ExpiredBackup) error {
		if e.ExpirationType == backups.ExpireGarbageCollection {
			pending = e
		}
		return nil
	})
	if len(pending.HashedBackupID) == 0 {
		t.Fatal("no pending-deletion row found")
	}

	// StartExpiration is a no-op for the memory backend.
	if err := s.StartExpiration(ctx, pending); err != nil {
		t.Errorf("StartExpiration: %v", err)
	}
	// FinishExpiration clears the row.
	if err := s.FinishExpiration(ctx, pending); err != nil {
		t.Errorf("FinishExpiration: %v", err)
	}
	// After finish, no GC rows remain.
	var stillThere bool
	_ = s.GetExpiredBackups(ctx, 1, time.Now().Add(time.Hour), func(e backups.ExpiredBackup) error {
		if e.ExpirationType == backups.ExpireGarbageCollection {
			stillThere = true
		}
		return nil
	})
	if stillThere {
		t.Error("pending row not cleared by FinishExpiration")
	}
}

func TestMemoryRedeemedReceiptsStore_FirstRedemptionIdempotent(t *testing.T) {
	s := NewMemoryRedeemedReceiptsStore()
	ctx := context.Background()
	serial := []byte{1, 2, 3, 4}
	exp := time.Now().Add(time.Hour)

	ok, err := s.Put(ctx, serial, exp, 201, "acct-a")
	if err != nil || !ok {
		t.Fatalf("first Put ok=%v err=%v", ok, err)
	}

	// Same account re-redeems: accepted (idempotent).
	ok, err = s.Put(ctx, serial, exp, 201, "acct-a")
	if err != nil || !ok {
		t.Fatalf("idempotent Put ok=%v err=%v", ok, err)
	}

	// Different account: rejected.
	ok, err = s.Put(ctx, serial, exp, 201, "acct-b")
	if err != nil || ok {
		t.Fatalf("cross-account Put should reject: ok=%v err=%v", ok, err)
	}
}

func TestMemoryRedeemedReceiptsStore_ExpiredEntryLazyEvicted(t *testing.T) {
	s := NewMemoryRedeemedReceiptsStore()
	ctx := context.Background()
	serial := []byte{9, 9, 9, 9}
	exp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := s.Put(ctx, serial, exp, 201, "acct-a"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Advance the clock past expiration.
	s.SetClock(func() time.Time { return exp.Add(time.Hour) })

	// A different account should now succeed because the prior entry
	// was lazily evicted on read.
	ok, err := s.Put(ctx, serial, time.Now().Add(24*time.Hour), 201, "acct-b")
	if err != nil || !ok {
		t.Fatalf("post-expiration Put: ok=%v err=%v", ok, err)
	}
}
