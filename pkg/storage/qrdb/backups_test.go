package qrdb

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/backups"
)

// faultyKVScan wraps a FakeKVStore and returns scanErr on all Scan calls.
type faultyKVScan struct {
	*FakeKVStore
	scanErr error
}

func (f *faultyKVScan) Scan(_ context.Context, _ string, _ func(string, []byte) error) error {
	return f.scanErr
}

// newBackupID returns a [backups.BackupID] with every byte set to b.
func newBackupID(b byte) backups.BackupID {
	var id backups.BackupID
	for i := range id {
		id[i] = b
	}
	return id
}

// newUser constructs a minimal [backups.AuthenticatedUser] for a given id and
// credential type, using stable placeholder directory names.
func newUser(id backups.BackupID, ct backups.CredentialType) backups.AuthenticatedUser {
	return backups.AuthenticatedUser{
		BackupID:       id,
		CredentialType: ct,
		BackupLevel:    backups.BackupLevelFree,
		BackupDir:      "dir",
		MediaDir:       "media",
	}
}

// newBackupStore returns a BackupStore backed by a fresh FakeKVStore.
func newBackupStore() *BackupStore {
	return NewBackupStore(NewFakeKVStore())
}

// newRedeemedReceiptsStore returns a RedeemedReceiptsStore backed by a fresh FakeKVStore.
func newRedeemedReceiptsStore() *RedeemedReceiptsStore {
	return NewRedeemedReceiptsStore(NewFakeKVStore())
}

// ---- SetPublicKey ------------------------------------------------------------

func TestQrdbBackupStore_SetPublicKey_FirstAndConflict(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()
	id := newBackupID(0xAA)

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

func TestQrdbBackupStore_RetrieveAuthenticationData_HappyAndMissing(t *testing.T) {
	s := newBackupStore()
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
		t.Errorf("public key mismatch: got %x want %x", data.PublicKey, pk)
	}
	if data.BackupDir == "" || data.MediaDir == "" {
		t.Errorf("backup/media dir not seeded: %+v", data)
	}

	// Missing id → ok=false, no error.
	_, ok, err = s.RetrieveAuthenticationData(ctx, newBackupID(0x22))
	if err != nil || ok {
		t.Errorf("missing id should return ok=false, got ok=%v err=%v", ok, err)
	}
}

// ---- TTLRefresh -------------------------------------------------------------

func TestQrdbBackupStore_TTLRefresh_UpdatesTimestamps(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()
	id := newBackupID(0x33)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}

	t0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return t0 })

	msgUser := newUser(id, backups.CredentialTypeMessages)
	attrs, err := s.TTLRefresh(ctx, msgUser)
	if err != nil {
		t.Fatalf("TTLRefresh messages: %v", err)
	}
	if !attrs.LastRefresh.Equal(t0) {
		t.Errorf("LastRefresh = %v; want %v", attrs.LastRefresh, t0)
	}

	// Media credential bumps LastMediaRefresh.
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
	_, err = s.TTLRefresh(ctx, newUser(newBackupID(0x44), backups.CredentialTypeMessages))
	var nf *backups.NotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *NotFoundError on missing id, got %T: %v", err, err)
	}
}

// ---- AddMessageBackup -------------------------------------------------------

func TestQrdbBackupStore_AddMessageBackup_BumpsLastRefresh(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()
	id := newBackupID(0xA1)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}

	t1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return t1 })
	user := newUser(id, backups.CredentialTypeMessages)
	if err := s.AddMessageBackup(ctx, user); err != nil {
		t.Fatalf("AddMessageBackup: %v", err)
	}
	// TTLRefresh returns the updated row; verify timestamp.
	attrs, err := s.TTLRefresh(ctx, user)
	if err != nil {
		t.Fatalf("TTLRefresh: %v", err)
	}
	if !attrs.LastRefresh.Equal(t1) {
		t.Errorf("LastRefresh after AddMessageBackup = %v; want %v", attrs.LastRefresh, t1)
	}

	// Unknown id → error.
	if err := s.AddMessageBackup(ctx, newUser(newBackupID(0xA2), backups.CredentialTypeMessages)); err == nil {
		t.Error("expected error for unknown id")
	}
}

// ---- TrackMedia + GetMediaUsage ---------------------------------------------

func TestQrdbBackupStore_TrackMedia_AndUsageRoundTrip(t *testing.T) {
	s := newBackupStore()
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

	// Negative delta refunds; clamps at zero — never negative.
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

func TestQrdbBackupStore_SetMediaUsage_OverwritesAndStampsRecalc(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()
	id := newBackupID(0x56)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	user := newUser(id, backups.CredentialTypeMedia)
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
	if !usage.LastRecalculationTime.Equal(t0) {
		t.Errorf("recalc time = %v; want %v", usage.LastRecalculationTime, t0)
	}
}

// ---- SetMediaUsageFor -------------------------------------------------------

func TestQrdbBackupStore_SetMediaUsageFor_WorkerPath(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()
	id := newBackupID(0xA3)
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
	user := newUser(id, backups.CredentialTypeMedia)
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
	if err := s.SetMediaUsageFor(ctx, bogus, backups.UsageInfo{}); err == nil {
		t.Error("expected NotFoundError on unknown hash")
	}
}

// ---- DescribeBackup ---------------------------------------------------------

func TestQrdbBackupStore_DescribeBackup_TypeAware(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()
	id := newBackupID(0x66)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	user := newUser(id, backups.CredentialTypeMedia)
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

func TestQrdbBackupStore_ScheduleDeletion_RotatesDirsAndQueuesPending(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()
	id := newBackupID(0x77)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	data, _, err := s.RetrieveAuthenticationData(ctx, id)
	if err != nil {
		t.Fatalf("RetrieveAuthenticationData: %v", err)
	}
	originalDir := data.BackupDir

	user := newUser(id, backups.CredentialTypeMessages)
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

	// A second schedule against the freshly-rotated dir also succeeds, just
	// like the memory backend. PendingDeletionError only fires when the stored
	// entry's current backupDir already has a queued pending row (which cannot
	// happen in normal sequential use because each call rotates the dir first).
	user.BackupDir = dataAfter.BackupDir
	user.MediaDir = dataAfter.MediaDir
	if err := s.ScheduleBackupDeletion(ctx, user); err != nil {
		t.Fatalf("second ScheduleBackupDeletion (rotated dir): %v", err)
	}

	// The pending rows surface as ExpireGarbageCollection.
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
		t.Error("expected at least one ExpireGarbageCollection row in GetExpiredBackups")
	}
}

// ---- ListBackupAttributes ---------------------------------------------------

func TestQrdbBackupStore_ListBackupAttributes_StreamsAll(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()
	for i := byte(1); i <= 5; i++ {
		if err := s.SetPublicKey(ctx, newBackupID(i), backups.BackupLevelFree, []byte{i}); err != nil {
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

func TestQrdbBackupStore_StartFinishExpiration_PendingLifecycle(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()
	id := newBackupID(0xA4)
	if err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
	data, _, err := s.RetrieveAuthenticationData(ctx, id)
	if err != nil {
		t.Fatalf("RetrieveAuthenticationData: %v", err)
	}
	user := newUser(id, backups.CredentialTypeMessages)
	user.BackupDir = data.BackupDir
	user.MediaDir = data.MediaDir
	if err := s.ScheduleBackupDeletion(ctx, user); err != nil {
		t.Fatalf("ScheduleBackupDeletion: %v", err)
	}

	// Find the pending row via GetExpiredBackups.
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

	// StartExpiration is a no-op for the qrdb backend.
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

func TestQrdbBackupStore_GetExpiredBackups_ReturnsExpiredRows(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()

	// Plant two entries with old timestamps.
	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return old })
	for _, b := range []byte{0xE1, 0xE2} {
		if err := s.SetPublicKey(ctx, newBackupID(b), backups.BackupLevelFree, []byte{b}); err != nil {
			t.Fatalf("SetPublicKey: %v", err)
		}
	}
	// Plant one entry with a future timestamp.
	fresh := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return fresh })
	if err := s.SetPublicKey(ctx, newBackupID(0xE3), backups.BackupLevelFree, []byte{0xE3}); err != nil {
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

func TestQrdbRedeemedReceiptsStore_FirstRedemptionIdempotent(t *testing.T) {
	s := newRedeemedReceiptsStore()
	ctx := context.Background()
	serial := []byte{1, 2, 3, 4}
	exp := time.Now().Add(time.Hour)

	ok, err := s.Put(ctx, serial, exp, 201, "acct-a")
	if err != nil || !ok {
		t.Fatalf("first Put ok=%v err=%v", ok, err)
	}
	// Same account re-redeems: idempotent, accepted.
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

func TestQrdbRedeemedReceiptsStore_ExpiredEntryLazyEvicted(t *testing.T) {
	s := newRedeemedReceiptsStore()
	ctx := context.Background()
	serial := []byte{9, 9, 9, 9}
	exp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := s.Put(ctx, serial, exp, 201, "acct-a"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Advance the clock past expiration so the entry is treated as expired.
	s.SetClock(func() time.Time { return exp.Add(time.Hour) })

	// A different account must now succeed because the prior entry was
	// lazily evicted on read.
	ok, err := s.Put(ctx, serial, time.Now().Add(24*time.Hour), 201, "acct-b")
	if err != nil || !ok {
		t.Fatalf("post-expiration Put: ok=%v err=%v", ok, err)
	}
}

// ---- Error path coverage ----------------------------------------------------

// errBoom is a stable test sentinel for KV-layer failures.
var errBoom = errors.New("backend exploded")

func TestQrdbBackupStore_SetPublicKey_GetError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: errBoom}
	s := NewBackupStore(kv)
	err := s.SetPublicKey(context.Background(), newBackupID(0x01), backups.BackupLevelFree, []byte("pk"))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_SetPublicKey_PutError(t *testing.T) {
	// Seed a key so the Get succeeds but Put fails on save.
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewBackupStore(kv)
	ctx := context.Background()
	// First insert succeeds; then inject put error.
	id := newBackupID(0x02)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk1"))
	kv.putErr = errBoom
	err := s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk1"))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom on save, got %v", err)
	}
}

func TestQrdbBackupStore_RetrieveAuthenticationData_GetError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: errBoom}
	s := NewBackupStore(kv)
	_, _, err := s.RetrieveAuthenticationData(context.Background(), newBackupID(0x03))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_AddMessageBackup_GetError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: errBoom}
	s := NewBackupStore(kv)
	err := s.AddMessageBackup(context.Background(), newUser(newBackupID(0x04), backups.CredentialTypeMessages))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_AddMessageBackup_PutError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewBackupStore(kv)
	ctx := context.Background()
	id := newBackupID(0x05)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk"))
	kv.putErr = errBoom
	if err := s.AddMessageBackup(ctx, newUser(id, backups.CredentialTypeMessages)); !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_TTLRefresh_GetError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: errBoom}
	s := NewBackupStore(kv)
	_, err := s.TTLRefresh(context.Background(), newUser(newBackupID(0x06), backups.CredentialTypeMessages))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_TTLRefresh_PutError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewBackupStore(kv)
	ctx := context.Background()
	id := newBackupID(0x07)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk"))
	kv.putErr = errBoom
	if _, err := s.TTLRefresh(ctx, newUser(id, backups.CredentialTypeMessages)); !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_DescribeBackup_GetError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: errBoom}
	s := NewBackupStore(kv)
	_, err := s.DescribeBackup(context.Background(), newUser(newBackupID(0x08), backups.CredentialTypeMedia))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_DescribeBackup_NotFound(t *testing.T) {
	s := newBackupStore()
	_, err := s.DescribeBackup(context.Background(), newUser(newBackupID(0x09), backups.CredentialTypeMedia))
	var nf *backups.NotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *NotFoundError, got %T: %v", err, err)
	}
}

func TestQrdbBackupStore_TrackMedia_GetError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: errBoom}
	s := NewBackupStore(kv)
	err := s.TrackMedia(context.Background(), newUser(newBackupID(0x0A), backups.CredentialTypeMedia), 1, 1)
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_TrackMedia_PutError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewBackupStore(kv)
	ctx := context.Background()
	id := newBackupID(0x0B)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk"))
	kv.putErr = errBoom
	user := newUser(id, backups.CredentialTypeMedia)
	user.BackupLevel = backups.BackupLevelPaid
	if err := s.TrackMedia(ctx, user, 1, 1); !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_GetMediaUsage_GetError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: errBoom}
	s := NewBackupStore(kv)
	_, err := s.GetMediaUsage(context.Background(), newUser(newBackupID(0x0C), backups.CredentialTypeMedia))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_GetMediaUsage_NotFound(t *testing.T) {
	s := newBackupStore()
	_, err := s.GetMediaUsage(context.Background(), newUser(newBackupID(0x0D), backups.CredentialTypeMedia))
	var nf *backups.NotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *NotFoundError, got %T: %v", err, err)
	}
}

func TestQrdbBackupStore_SetMediaUsage_GetError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: errBoom}
	s := NewBackupStore(kv)
	err := s.SetMediaUsage(context.Background(), newUser(newBackupID(0x0E), backups.CredentialTypeMedia), backups.UsageInfo{})
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_SetMediaUsage_NotFound(t *testing.T) {
	s := newBackupStore()
	err := s.SetMediaUsage(context.Background(), newUser(newBackupID(0x0F), backups.CredentialTypeMedia), backups.UsageInfo{})
	var nf *backups.NotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *NotFoundError, got %T: %v", err, err)
	}
}

func TestQrdbBackupStore_SetMediaUsage_PutError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewBackupStore(kv)
	ctx := context.Background()
	id := newBackupID(0x10)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk"))
	kv.putErr = errBoom
	user := newUser(id, backups.CredentialTypeMedia)
	user.BackupLevel = backups.BackupLevelPaid
	if err := s.SetMediaUsage(ctx, user, backups.UsageInfo{}); !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_SetMediaUsageFor_GetError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: errBoom}
	s := NewBackupStore(kv)
	err := s.SetMediaUsageFor(context.Background(), backups.StoredAttributes{HashedBackupID: []byte{1, 2, 3}}, backups.UsageInfo{})
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_ScheduleBackupDeletion_GetError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: errBoom}
	s := NewBackupStore(kv)
	err := s.ScheduleBackupDeletion(context.Background(), newUser(newBackupID(0x11), backups.CredentialTypeMessages))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_ScheduleBackupDeletion_NotFound(t *testing.T) {
	s := newBackupStore()
	err := s.ScheduleBackupDeletion(context.Background(), newUser(newBackupID(0x12), backups.CredentialTypeMessages))
	var nf *backups.NotFoundError
	if !errors.As(err, &nf) {
		t.Errorf("expected *NotFoundError, got %T: %v", err, err)
	}
}

func TestQrdbBackupStore_ScheduleBackupDeletion_ExistsError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewBackupStore(kv)
	ctx := context.Background()
	id := newBackupID(0x13)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk"))
	kv.existsErr = errBoom
	err := s.ScheduleBackupDeletion(ctx, newUser(id, backups.CredentialTypeMessages))
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_ScheduleBackupDeletion_PendingDeletionError(t *testing.T) {
	// To trigger PendingDeletionError we must arrange for the pending key to
	// exist BEFORE the call. We do that by writing the pending entry directly
	// to the fake KV using the same key formula the implementation uses.
	kv := NewFakeKVStore()
	s := NewBackupStore(kv)
	ctx := context.Background()
	id := newBackupID(0x14)
	_ = s.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk"))

	// Fetch the stored entry to learn HashedBackupID and current BackupDir.
	var storedAttrs backups.StoredAttributes
	_ = s.ListBackupAttributes(ctx, 1, func(a backups.StoredAttributes) error {
		storedAttrs = a
		return nil
	})
	// Manually write the pending key so Exists returns true.
	pk := pendingKey(storedAttrs.HashedBackupID, storedAttrs.BackupDir)
	_ = kv.Put(ctx, pk, []byte(`{}`))

	err := s.ScheduleBackupDeletion(ctx, newUser(id, backups.CredentialTypeMessages))
	var pe *backups.PendingDeletionError
	if !errors.As(err, &pe) {
		t.Errorf("expected *PendingDeletionError, got %T: %v", err, err)
	}
}

func TestQrdbBackupStore_ListBackupAttributes_ScanError(t *testing.T) {
	kv := &faultyKVScan{FakeKVStore: NewFakeKVStore(), scanErr: errBoom}
	s := NewBackupStore(kv)
	err := s.ListBackupAttributes(context.Background(), 1, func(_ backups.StoredAttributes) error { return nil })
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_ListBackupAttributes_CallbackError(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()
	_ = s.SetPublicKey(ctx, newBackupID(0x15), backups.BackupLevelFree, []byte("pk"))
	cbErr := errors.New("callback failed")
	err := s.ListBackupAttributes(ctx, 1, func(_ backups.StoredAttributes) error { return cbErr })
	if !errors.Is(err, cbErr) {
		t.Errorf("expected cbErr, got %v", err)
	}
}

func TestQrdbBackupStore_GetExpiredBackups_ScanError(t *testing.T) {
	kv := &faultyKVScan{FakeKVStore: NewFakeKVStore(), scanErr: errBoom}
	s := NewBackupStore(kv)
	err := s.GetExpiredBackups(context.Background(), 1, time.Now(), func(_ backups.ExpiredBackup) error { return nil })
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbBackupStore_GetExpiredBackups_CallbackError(t *testing.T) {
	s := newBackupStore()
	ctx := context.Background()
	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return old })
	_ = s.SetPublicKey(ctx, newBackupID(0x16), backups.BackupLevelFree, []byte("pk"))
	purge := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cbErr := errors.New("callback failed")
	err := s.GetExpiredBackups(ctx, 1, purge, func(_ backups.ExpiredBackup) error { return cbErr })
	if !errors.Is(err, cbErr) {
		t.Errorf("expected cbErr, got %v", err)
	}
}

func TestQrdbRedeemedReceiptsStore_Put_GetError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), getErr: errBoom}
	s := NewRedeemedReceiptsStore(kv)
	_, err := s.Put(context.Background(), []byte{1}, time.Now().Add(time.Hour), 1, "acct")
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbRedeemedReceiptsStore_Put_PutError(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore(), putErr: errBoom}
	s := NewRedeemedReceiptsStore(kv)
	_, err := s.Put(context.Background(), []byte{2}, time.Now().Add(time.Hour), 1, "acct")
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom, got %v", err)
	}
}

func TestQrdbRedeemedReceiptsStore_Put_DeleteError_OnExpiry(t *testing.T) {
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewRedeemedReceiptsStore(kv)
	ctx := context.Background()
	serial := []byte{0xF0}
	exp := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	_, _ = s.Put(ctx, serial, exp, 1, "acct-a")
	// Move clock past expiry so the existing entry is treated as expired
	// and Delete is called. Then inject delete error.
	s.SetClock(func() time.Time { return exp.Add(time.Hour) })
	kv.deleteErr = errBoom
	_, err := s.Put(ctx, serial, time.Now().Add(time.Hour), 1, "acct-b")
	if !errors.Is(err, errBoom) {
		t.Errorf("expected errBoom on delete during lazy eviction, got %v", err)
	}
}
