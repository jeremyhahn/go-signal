package storage_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/backups"
	memorystorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// backendFactory bundles a name with a function that produces a fresh
// (backups.Store, backups.RedeemedReceiptsStore) pair for one test.
type backendFactory struct {
	name string
	new  func(t *testing.T) (backups.Store, backups.RedeemedReceiptsStore, clockSetter, receiptClockSetter)
}

// clockSetter is the optional clock-injection hook exposed by every backend's
// BackupStore for deterministic timestamp tests. nil means the backend doesn't
// support it (none currently skip this).
type clockSetter interface {
	SetClock(func() time.Time)
}

// receiptClockSetter is the same for the RedeemedReceiptsStore.
type receiptClockSetter interface {
	SetClock(func() time.Time)
}

// truncateBackups removes all rows from the three backup tables on postgres so
// each contract sub-test starts with a clean slate. Called only when postgres
// is active; it is idempotent.
func truncateBackups(ctx context.Context, c *postgres.Client) {
	const sql = `TRUNCATE TABLE backup_redeemed_receipts, backups_pending_deletion, backups RESTART IDENTITY CASCADE`
	_, _ = c.Pool().Exec(ctx, sql)
}

// backends returns one factory per registered backend. The postgres factory
// calls t.Skip when TEST_POSTGRES_URL is unset so memory + qrdb always run.
func backends(t *testing.T) []backendFactory {
	t.Helper()
	return []backendFactory{
		{
			name: "memory",
			new: func(t *testing.T) (backups.Store, backups.RedeemedReceiptsStore, clockSetter, receiptClockSetter) {
				t.Helper()
				bs := memorystorage.NewMemoryBackupStore()
				rs := memorystorage.NewMemoryRedeemedReceiptsStore()
				return bs, rs, bs, rs
			},
		},
		{
			name: "qrdb",
			new: func(t *testing.T) (backups.Store, backups.RedeemedReceiptsStore, clockSetter, receiptClockSetter) {
				t.Helper()
				bs := qrdbstorage.NewBackupStore(qrdbstorage.NewFakeKVStore())
				rs := qrdbstorage.NewRedeemedReceiptsStore(qrdbstorage.NewFakeKVStore())
				return bs, rs, bs, rs
			},
		},
		{
			name: "postgres",
			new: func(t *testing.T) (backups.Store, backups.RedeemedReceiptsStore, clockSetter, receiptClockSetter) {
				t.Helper()
				dsn := postgresEnv()
				if dsn == "" {
					t.Skipf("%s not set; skipping postgres backend", testPostgresEnv)
				}
				c := postgresClient(t)
				ctx := context.Background()
				truncateBackups(ctx, c)
				t.Cleanup(func() { truncateBackups(context.Background(), c) })
				bs := postgres.NewBackupStore(c)
				rs := postgres.NewRedeemedReceiptsStore(c)
				return bs, rs, bs, rs
			},
		},
	}
}

// newContractBackupID returns a [backups.BackupID] with every byte set to b.
func newContractBackupID(b byte) backups.BackupID {
	var id backups.BackupID
	for i := range id {
		id[i] = b
	}
	return id
}

// newContractUser builds a minimal [backups.AuthenticatedUser] for contract tests.
func newContractUser(id backups.BackupID, ct backups.CredentialType) backups.AuthenticatedUser {
	return backups.AuthenticatedUser{
		BackupID:       id,
		CredentialType: ct,
		BackupLevel:    backups.BackupLevelFree,
		BackupDir:      "dir",
		MediaDir:       "media",
	}
}

// postgresEnv returns the TEST_POSTGRES_URL environment variable value.
// It lets factory closures check the env before calling postgresClient(t),
// which would acquire the advisory lock and start the connection even for
// an immediate skip.
func postgresEnv() string {
	return os.Getenv(testPostgresEnv)
}

// ---- Contract: SetPublicKey -------------------------------------------------

func TestContract_SetPublicKey_FirstIdempotentConflict(t *testing.T) {
	for _, bf := range backends(t) {
		t.Run(bf.name, func(t *testing.T) {
			store, _, _, _ := bf.new(t)
			ctx := context.Background()
			id := newContractBackupID(0xAA)

			if err := store.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk1")); err != nil {
				t.Fatalf("[%s] first SetPublicKey: %v", bf.name, err)
			}
			// Idempotent same-key re-set.
			if err := store.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk1")); err != nil {
				t.Fatalf("[%s] repeat same-key SetPublicKey: %v", bf.name, err)
			}
			// Different key → *PublicKeyConflictError.
			err := store.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk2"))
			var conflict *backups.PublicKeyConflictError
			if !errors.As(err, &conflict) {
				t.Errorf("[%s] expected *PublicKeyConflictError, got %T: %v", bf.name, err, err)
			}
		})
	}
}

// ---- Contract: RetrieveAuthenticationData -----------------------------------

func TestContract_RetrieveAuthenticationData_HappyAndMissing(t *testing.T) {
	for _, bf := range backends(t) {
		t.Run(bf.name, func(t *testing.T) {
			store, _, _, _ := bf.new(t)
			ctx := context.Background()
			id := newContractBackupID(0x11)
			pk := []byte("contractpk")

			if err := store.SetPublicKey(ctx, id, backups.BackupLevelFree, pk); err != nil {
				t.Fatalf("[%s] SetPublicKey: %v", bf.name, err)
			}
			data, ok, err := store.RetrieveAuthenticationData(ctx, id)
			if err != nil || !ok {
				t.Fatalf("[%s] RetrieveAuthenticationData ok=%v err=%v", bf.name, ok, err)
			}
			if !bytes.Equal(data.PublicKey, pk) {
				t.Errorf("[%s] public key mismatch", bf.name)
			}
			if data.BackupDir == "" || data.MediaDir == "" {
				t.Errorf("[%s] backup/media dir not seeded", bf.name)
			}

			// Missing id → ok=false, no error.
			_, ok, err = store.RetrieveAuthenticationData(ctx, newContractBackupID(0x22))
			if err != nil || ok {
				t.Errorf("[%s] missing id should return ok=false, got ok=%v err=%v", bf.name, ok, err)
			}
		})
	}
}

// ---- Contract: AddMessageBackup ---------------------------------------------

func TestContract_AddMessageBackup_UnknownIDErrors(t *testing.T) {
	for _, bf := range backends(t) {
		t.Run(bf.name, func(t *testing.T) {
			store, _, _, _ := bf.new(t)
			ctx := context.Background()
			if err := store.AddMessageBackup(ctx, newContractUser(newContractBackupID(0xBB), backups.CredentialTypeMessages)); err == nil {
				t.Errorf("[%s] expected error for unknown id", bf.name)
			}
		})
	}
}

// ---- Contract: TTLRefresh ---------------------------------------------------

func TestContract_TTLRefresh_UpdatesTimestampsPerCredentialType(t *testing.T) {
	for _, bf := range backends(t) {
		t.Run(bf.name, func(t *testing.T) {
			store, _, cs, _ := bf.new(t)
			ctx := context.Background()
			id := newContractBackupID(0x33)
			if err := store.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
				t.Fatalf("[%s] SetPublicKey: %v", bf.name, err)
			}

			t0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
			cs.SetClock(func() time.Time { return t0 })

			msgUser := newContractUser(id, backups.CredentialTypeMessages)
			attrs, err := store.TTLRefresh(ctx, msgUser)
			if err != nil {
				t.Fatalf("[%s] TTLRefresh messages: %v", bf.name, err)
			}
			if !attrs.LastRefresh.UTC().Truncate(time.Second).Equal(t0) {
				t.Errorf("[%s] LastRefresh = %v; want %v", bf.name, attrs.LastRefresh.UTC().Truncate(time.Second), t0)
			}

			t1 := t0.Add(time.Hour)
			cs.SetClock(func() time.Time { return t1 })
			mediaUser := newContractUser(id, backups.CredentialTypeMedia)
			attrs, err = store.TTLRefresh(ctx, mediaUser)
			if err != nil {
				t.Fatalf("[%s] TTLRefresh media: %v", bf.name, err)
			}
			if !attrs.LastMediaRefresh.UTC().Truncate(time.Second).Equal(t1) {
				t.Errorf("[%s] LastMediaRefresh = %v; want %v", bf.name, attrs.LastMediaRefresh.UTC().Truncate(time.Second), t1)
			}

			// Unknown id → error.
			_, err = store.TTLRefresh(ctx, newContractUser(newContractBackupID(0x44), backups.CredentialTypeMessages))
			if err == nil {
				t.Errorf("[%s] expected error for TTLRefresh on missing id", bf.name)
			}
		})
	}
}

// ---- Contract: TrackMedia + GetMediaUsage -----------------------------------

func TestContract_TrackMedia_AccumulatesAndRefundsClampAtZero(t *testing.T) {
	for _, bf := range backends(t) {
		t.Run(bf.name, func(t *testing.T) {
			store, _, _, _ := bf.new(t)
			ctx := context.Background()
			id := newContractBackupID(0x55)
			if err := store.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk")); err != nil {
				t.Fatalf("[%s] SetPublicKey: %v", bf.name, err)
			}
			user := newContractUser(id, backups.CredentialTypeMedia)
			user.BackupLevel = backups.BackupLevelPaid

			// Positive delta accumulates.
			if err := store.TrackMedia(ctx, user, 3, 100); err != nil {
				t.Fatalf("[%s] TrackMedia +: %v", bf.name, err)
			}
			usage, err := store.GetMediaUsage(ctx, user)
			if err != nil {
				t.Fatalf("[%s] GetMediaUsage: %v", bf.name, err)
			}
			if usage.Usage.BytesUsed != 100 || usage.Usage.NumObjects != 3 {
				t.Errorf("[%s] usage = %+v; want bytes=100 count=3", bf.name, usage.Usage)
			}

			// Negative delta refunds and must never go below zero.
			if err := store.TrackMedia(ctx, user, -10, -1000); err != nil {
				t.Fatalf("[%s] TrackMedia -: %v", bf.name, err)
			}
			usage, err = store.GetMediaUsage(ctx, user)
			if err != nil {
				t.Fatalf("[%s] GetMediaUsage after refund: %v", bf.name, err)
			}
			if usage.Usage.BytesUsed < 0 || usage.Usage.NumObjects < 0 {
				t.Errorf("[%s] usage went negative: %+v", bf.name, usage.Usage)
			}
			if usage.Usage.BytesUsed != 0 || usage.Usage.NumObjects != 0 {
				t.Errorf("[%s] after refund: usage = %+v; want zeros", bf.name, usage.Usage)
			}
		})
	}
}

// ---- Contract: DescribeBackup -----------------------------------------------

func TestContract_DescribeBackup_MediaIncludesUsedSpace_MessagesDoesNot(t *testing.T) {
	for _, bf := range backends(t) {
		t.Run(bf.name, func(t *testing.T) {
			store, _, _, _ := bf.new(t)
			ctx := context.Background()
			id := newContractBackupID(0x66)
			if err := store.SetPublicKey(ctx, id, backups.BackupLevelPaid, []byte("pk")); err != nil {
				t.Fatalf("[%s] SetPublicKey: %v", bf.name, err)
			}
			user := newContractUser(id, backups.CredentialTypeMedia)
			user.BackupLevel = backups.BackupLevelPaid
			if err := store.TrackMedia(ctx, user, 1, 123); err != nil {
				t.Fatalf("[%s] TrackMedia: %v", bf.name, err)
			}

			descMedia, err := store.DescribeBackup(ctx, user)
			if err != nil {
				t.Fatalf("[%s] DescribeBackup media: %v", bf.name, err)
			}
			if descMedia.MediaUsedSpace == nil || *descMedia.MediaUsedSpace != 123 {
				t.Errorf("[%s] media describe used = %v; want 123", bf.name, descMedia.MediaUsedSpace)
			}

			user.CredentialType = backups.CredentialTypeMessages
			descMessages, err := store.DescribeBackup(ctx, user)
			if err != nil {
				t.Fatalf("[%s] DescribeBackup messages: %v", bf.name, err)
			}
			if descMessages.MediaUsedSpace != nil {
				t.Errorf("[%s] messages describe should not include media usage", bf.name)
			}
		})
	}
}

// ---- Contract: ScheduleBackupDeletion ---------------------------------------

func TestContract_ScheduleBackupDeletion_RotatesDirAndQueuesPending(t *testing.T) {
	for _, bf := range backends(t) {
		t.Run(bf.name, func(t *testing.T) {
			store, _, _, _ := bf.new(t)
			ctx := context.Background()
			id := newContractBackupID(0x77)
			if err := store.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
				t.Fatalf("[%s] SetPublicKey: %v", bf.name, err)
			}
			data, _, err := store.RetrieveAuthenticationData(ctx, id)
			if err != nil {
				t.Fatalf("[%s] RetrieveAuthenticationData: %v", bf.name, err)
			}
			originalDir := data.BackupDir

			user := newContractUser(id, backups.CredentialTypeMessages)
			user.BackupDir = data.BackupDir
			user.MediaDir = data.MediaDir
			if err := store.ScheduleBackupDeletion(ctx, user); err != nil {
				t.Fatalf("[%s] ScheduleBackupDeletion: %v", bf.name, err)
			}

			dataAfter, _, err := store.RetrieveAuthenticationData(ctx, id)
			if err != nil {
				t.Fatalf("[%s] RetrieveAuthenticationData after schedule: %v", bf.name, err)
			}
			if dataAfter.BackupDir == originalDir {
				t.Errorf("[%s] backupDir should be rotated after schedule", bf.name)
			}

			// A second schedule against the newly-rotated dir succeeds and
			// produces another pending row. PendingDeletionError fires only
			// when the stored entry's current dir already has a queued row,
			// which cannot occur in normal sequential use.
			user.BackupDir = dataAfter.BackupDir
			user.MediaDir = dataAfter.MediaDir
			if err := store.ScheduleBackupDeletion(ctx, user); err != nil {
				t.Fatalf("[%s] second ScheduleBackupDeletion (rotated dir): %v", bf.name, err)
			}

			// The pending rows surface as ExpireGarbageCollection entries.
			var gcCount int
			if err := store.GetExpiredBackups(ctx, 1, time.Now().Add(time.Hour), func(e backups.ExpiredBackup) error {
				if e.ExpirationType == backups.ExpireGarbageCollection {
					gcCount++
				}
				return nil
			}); err != nil {
				t.Fatalf("[%s] GetExpiredBackups: %v", bf.name, err)
			}
			if gcCount < 1 {
				t.Errorf("[%s] expected at least one ExpireGarbageCollection row, got %d", bf.name, gcCount)
			}
		})
	}
}

// ---- Contract: StartExpiration / FinishExpiration ---------------------------

func TestContract_StartExpiration_FinishExpiration_ClearsPendingRow(t *testing.T) {
	for _, bf := range backends(t) {
		t.Run(bf.name, func(t *testing.T) {
			store, _, _, _ := bf.new(t)
			ctx := context.Background()
			id := newContractBackupID(0xA4)
			if err := store.SetPublicKey(ctx, id, backups.BackupLevelFree, []byte("pk")); err != nil {
				t.Fatalf("[%s] SetPublicKey: %v", bf.name, err)
			}
			data, _, err := store.RetrieveAuthenticationData(ctx, id)
			if err != nil {
				t.Fatalf("[%s] RetrieveAuthenticationData: %v", bf.name, err)
			}
			user := newContractUser(id, backups.CredentialTypeMessages)
			user.BackupDir = data.BackupDir
			user.MediaDir = data.MediaDir
			if err := store.ScheduleBackupDeletion(ctx, user); err != nil {
				t.Fatalf("[%s] ScheduleBackupDeletion: %v", bf.name, err)
			}

			var pending backups.ExpiredBackup
			if err := store.GetExpiredBackups(ctx, 1, time.Now().Add(time.Hour), func(e backups.ExpiredBackup) error {
				if e.ExpirationType == backups.ExpireGarbageCollection {
					pending = e
				}
				return nil
			}); err != nil {
				t.Fatalf("[%s] GetExpiredBackups: %v", bf.name, err)
			}
			if len(pending.HashedBackupID) == 0 {
				t.Fatalf("[%s] no pending-deletion row found", bf.name)
			}

			if err := store.StartExpiration(ctx, pending); err != nil {
				t.Errorf("[%s] StartExpiration: %v", bf.name, err)
			}
			if err := store.FinishExpiration(ctx, pending); err != nil {
				t.Errorf("[%s] FinishExpiration: %v", bf.name, err)
			}

			var stillThere bool
			if err := store.GetExpiredBackups(ctx, 1, time.Now().Add(time.Hour), func(e backups.ExpiredBackup) error {
				if e.ExpirationType == backups.ExpireGarbageCollection {
					stillThere = true
				}
				return nil
			}); err != nil {
				t.Fatalf("[%s] GetExpiredBackups after finish: %v", bf.name, err)
			}
			if stillThere {
				t.Errorf("[%s] pending row not cleared by FinishExpiration", bf.name)
			}
		})
	}
}

// ---- Contract: ListBackupAttributes -----------------------------------------

func TestContract_ListBackupAttributes_StreamsAllRows(t *testing.T) {
	for _, bf := range backends(t) {
		t.Run(bf.name, func(t *testing.T) {
			store, _, _, _ := bf.new(t)
			ctx := context.Background()
			for i := byte(1); i <= 5; i++ {
				if err := store.SetPublicKey(ctx, newContractBackupID(i), backups.BackupLevelFree, []byte{i}); err != nil {
					t.Fatalf("[%s] SetPublicKey %d: %v", bf.name, i, err)
				}
			}
			var count int
			if err := store.ListBackupAttributes(ctx, 1, func(attrs backups.StoredAttributes) error {
				count++
				if len(attrs.HashedBackupID) != 16 {
					t.Errorf("[%s] HashedBackupID len = %d; want 16", bf.name, len(attrs.HashedBackupID))
				}
				return nil
			}); err != nil {
				t.Fatalf("[%s] ListBackupAttributes: %v", bf.name, err)
			}
			if count != 5 {
				t.Errorf("[%s] count = %d; want 5", bf.name, count)
			}
		})
	}
}

// ---- Contract: GetExpiredBackups --------------------------------------------

func TestContract_GetExpiredBackups_ReturnsExpiredAndGCRows(t *testing.T) {
	for _, bf := range backends(t) {
		t.Run(bf.name, func(t *testing.T) {
			store, _, cs, _ := bf.new(t)
			ctx := context.Background()

			// Two entries with old timestamps.
			old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
			cs.SetClock(func() time.Time { return old })
			for _, b := range []byte{0xE1, 0xE2} {
				if err := store.SetPublicKey(ctx, newContractBackupID(b), backups.BackupLevelFree, []byte{b}); err != nil {
					t.Fatalf("[%s] SetPublicKey: %v", bf.name, err)
				}
			}

			// One entry with a future timestamp — must not appear as expired.
			future := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
			cs.SetClock(func() time.Time { return future })
			if err := store.SetPublicKey(ctx, newContractBackupID(0xE3), backups.BackupLevelFree, []byte{0xE3}); err != nil {
				t.Fatalf("[%s] SetPublicKey fresh: %v", bf.name, err)
			}

			purge := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			var count int
			if err := store.GetExpiredBackups(ctx, 1, purge, func(_ backups.ExpiredBackup) error {
				count++
				return nil
			}); err != nil {
				t.Fatalf("[%s] GetExpiredBackups: %v", bf.name, err)
			}
			if count != 2 {
				t.Errorf("[%s] expired count = %d; want 2", bf.name, count)
			}

			// Schedule a deletion; the resulting GC row must surface too.
			cs.SetClock(func() time.Time { return old })
			data, _, err := store.RetrieveAuthenticationData(ctx, newContractBackupID(0xE1))
			if err != nil {
				t.Fatalf("[%s] RetrieveAuthenticationData: %v", bf.name, err)
			}
			user := newContractUser(newContractBackupID(0xE1), backups.CredentialTypeMessages)
			user.BackupDir = data.BackupDir
			user.MediaDir = data.MediaDir
			if err := store.ScheduleBackupDeletion(ctx, user); err != nil {
				t.Fatalf("[%s] ScheduleBackupDeletion: %v", bf.name, err)
			}

			var gcCount int
			if err := store.GetExpiredBackups(ctx, 1, time.Now().Add(time.Hour), func(e backups.ExpiredBackup) error {
				if e.ExpirationType == backups.ExpireGarbageCollection {
					gcCount++
				}
				return nil
			}); err != nil {
				t.Fatalf("[%s] GetExpiredBackups for GC: %v", bf.name, err)
			}
			if gcCount < 1 {
				t.Errorf("[%s] expected at least one ExpireGarbageCollection row, got %d", bf.name, gcCount)
			}
		})
	}
}

// ---- Contract: RedeemedReceipts.Put -----------------------------------------

func TestContract_RedeemedReceiptsPut_FirstTrueIdempotentTrueCrossAccountFalse(t *testing.T) {
	for _, bf := range backends(t) {
		t.Run(bf.name, func(t *testing.T) {
			_, receipts, _, _ := bf.new(t)
			ctx := context.Background()
			serial := []byte{0xDE, 0xAD, 0xBE, 0xEF}
			exp := time.Now().Add(time.Hour)

			// First redemption → true.
			ok, err := receipts.Put(ctx, serial, exp, 201, "acct-a")
			if err != nil || !ok {
				t.Fatalf("[%s] first Put ok=%v err=%v", bf.name, ok, err)
			}
			// Same-account same-params idempotent → true.
			ok, err = receipts.Put(ctx, serial, exp, 201, "acct-a")
			if err != nil || !ok {
				t.Fatalf("[%s] idempotent Put ok=%v err=%v", bf.name, ok, err)
			}
			// Different account → false.
			ok, err = receipts.Put(ctx, serial, exp, 201, "acct-b")
			if err != nil || ok {
				t.Logf("DIVERGENCE: %s — cross-account Put returned ok=%v; want false", bf.name, ok)
				t.Errorf("[%s] cross-account Put should return false, got ok=%v err=%v", bf.name, ok, err)
			}
		})
	}
}
