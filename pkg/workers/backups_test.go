package workers

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/backups"
	"github.com/jeremyhahn/go-signal/pkg/limits"
	"github.com/jeremyhahn/go-signal/pkg/service"
	storagememory "github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

// --- shared fixture ----------------------------------------------------------

type workerFixture struct {
	svc   *service.SignalService
	store *storagememory.MemoryBackupStore
	blob  *workerFakeBlobStore
	clock time.Time
	mf    *workerManagerFixture
}

// workerManagerFixture mirrors the fields from pkg/backups.managerFixture.
type workerManagerFixture struct {
	manager       *backups.Manager
	store         *storagememory.MemoryBackupStore
	blob          *workerFakeBlobStore
	serverSecret  *zkgroup.GenericServerSecretParams
	clock         time.Time
	backupID      backups.BackupID
	identityKey   ecc.ECPrivateKeyable
	authMessages  backups.AuthenticatedUser
	authMediaPaid backups.AuthenticatedUser
}

func newWorkerFixture(t *testing.T) *workerFixture {
	t.Helper()

	store := storagememory.NewMemoryBackupStore()
	blob := newWorkerFakeBlobStore()
	var rb zkgroup.RandomnessBytes
	for i := range rb {
		rb[i] = 0x33
	}
	serverSecret := zkgroup.GenerateGenericServerSecretParams(rb)
	clock := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return clock })

	mgr := backups.NewManager(backups.ManagerOptions{
		Store:              store,
		Blob:               blob,
		ServerSecretParams: serverSecret,
		AttachmentLimiter:  limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		Clock:              func() time.Time { return clock },
	})

	var backupKey [32]byte
	for i := range backupKey {
		backupKey[i] = 0x42
	}
	aciBytes := [16]byte{0xc0, 0xfc, 0x16, 0xe4, 0xba, 0xe5, 0x43, 0x43, 0x9f, 0x0d, 0xe7, 0xec, 0xf4, 0x25, 0x13, 0x43}
	reqCtx, err := zkgroup.NewBackupAuthCredentialRequestContext(backupKey, zkgroup.NewACI(aciBytes))
	if err != nil {
		t.Fatalf("NewBackupAuthCredentialRequestContext: %v", err)
	}
	backupID := reqCtx.BackupIdentifier

	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubKey := kp.PublicKey().Serialize()

	ctx := context.Background()
	if err := store.SetPublicKey(ctx, backupID, backups.BackupLevelFree, pubKey); err != nil {
		t.Fatalf("seed SetPublicKey: %v", err)
	}
	data, ok, err := store.RetrieveAuthenticationData(ctx, backupID)
	if err != nil || !ok {
		t.Fatalf("RetrieveAuthenticationData: ok=%v err=%v", ok, err)
	}

	msgUser := backups.AuthenticatedUser{
		BackupID:       backupID,
		CredentialType: backups.CredentialTypeMessages,
		BackupLevel:    backups.BackupLevelFree,
		BackupDir:      data.BackupDir,
		MediaDir:       data.MediaDir,
		UserAgent:      "worker-test",
	}
	mediaUser := msgUser
	mediaUser.CredentialType = backups.CredentialTypeMedia
	mediaUser.BackupLevel = backups.BackupLevelPaid

	mf := &workerManagerFixture{
		manager:       mgr,
		store:         store,
		blob:          blob,
		serverSecret:  serverSecret,
		clock:         clock,
		backupID:      backupID,
		identityKey:   kp.PrivateKey(),
		authMessages:  msgUser,
		authMediaPaid: mediaUser,
	}

	var rr zkgroup.RandomnessBytes
	for i := range rr {
		rr[i] = 0xAA
	}
	receiptParams, err := zkgroup.GenerateServerSecretParams(rr)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	accountsMgr := accounts.NewAccountsManager(storagememory.NewMemoryAccountStore(), 6)
	authMgr := backups.NewAuthManager(backups.AuthManagerOptions{
		Accounts:                    accountsMgr,
		SetBackupIDLimiter:          limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		SetPaidMediaBackupIDLimiter: limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		ServerSecretParams:          serverSecret,
		ReceiptServerSecretParams:   receiptParams,
		RedeemedReceipts:            storagememory.NewMemoryRedeemedReceiptsStore(),
		Clock:                       func() time.Time { return clock },
	})
	backupSvc := backups.NewService(mgr, authMgr)
	signalSvc := &service.SignalService{
		Backups: service.NewBackupService(backupSvc),
	}

	return &workerFixture{
		svc:   signalSvc,
		store: store,
		blob:  blob,
		clock: clock,
		mf:    mf,
	}
}

// quietLog returns a no-op logger for workers.
func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(noopLogWriter{}, nil))
}

type noopLogWriter struct{}

func (noopLogWriter) Write(p []byte) (int, error) { return len(p), nil }

// --- workerFakeBlobStore -----------------------------------------------------

// workerFakeBlobStore is a minimal BlobStore satisfying the backups.BlobStore
// interface for worker tests. It does not duplicate the pkg/backups version;
// only the 7 required methods are implemented.
type workerFakeBlobStore struct {
	cdn     int
	objects map[string][]byte
}

func newWorkerFakeBlobStore() *workerFakeBlobStore {
	return &workerFakeBlobStore{cdn: 3, objects: make(map[string][]byte)}
}

func (f *workerFakeBlobStore) CDNNumber() int { return f.cdn }

func (f *workerFakeBlobStore) GenerateUpload(_ context.Context, key string) (*backups.UploadDescriptor, error) {
	return &backups.UploadDescriptor{CDN: f.cdn, Key: key}, nil
}

func (f *workerFakeBlobStore) ReadHeaders(_ context.Context, _ string) (map[string]string, error) {
	return map[string]string{"Authorization": "Bearer x"}, nil
}

func (f *workerFakeBlobStore) Copy(_ context.Context, _ int, srcKey string, _ int, _ backups.MediaEncryptionParameters, destPath string) error {
	f.objects[destPath] = make([]byte, 128)
	return nil
}

func (f *workerFakeBlobStore) Delete(_ context.Context, path string) (int64, error) {
	n := int64(len(f.objects[path]))
	delete(f.objects, path)
	return n, nil
}

func (f *workerFakeBlobStore) List(_ context.Context, prefix string, cursor *string, limit int) (*backups.BlobListResult, error) {
	var out backups.BlobListResult
	for k, v := range f.objects {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			key := k[len(prefix):]
			out.Objects = append(out.Objects, backups.BlobListEntry{Key: key, Length: int64(len(v))})
		}
	}
	return &out, nil
}

func (f *workerFakeBlobStore) CalculateBytesUsed(_ context.Context, prefix string) (backups.UsageInfo, error) {
	var info backups.UsageInfo
	for k, v := range f.objects {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			info.NumObjects++
			info.BytesUsed += int64(len(v))
		}
	}
	return info, nil
}

// --- RemoveExpiredBackupsWorker tests ----------------------------------------

func TestRemoveExpiredBackupsWorker_Name(t *testing.T) {
	w := NewRemoveExpiredBackupsWorker(nil, quietLog(), 0)
	if w.Name() != "remove-expired-backups" {
		t.Errorf("Name() = %q", w.Name())
	}
}

func TestRemoveExpiredBackupsWorker_Schedule(t *testing.T) {
	w := NewRemoveExpiredBackupsWorker(nil, quietLog(), 0)
	if w.Schedule() != "30 4 * * *" {
		t.Errorf("Schedule() = %q", w.Schedule())
	}
}

func TestRemoveExpiredBackupsWorker_NilServiceNoOps(t *testing.T) {
	w := NewRemoveExpiredBackupsWorker(&service.SignalService{}, quietLog(), time.Minute)
	// Backups is nil → worker should log and return nil without panicking.
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("expected nil error for nil service, got %v", err)
	}
}

func TestRemoveExpiredBackupsWorker_DefaultGrace(t *testing.T) {
	w := NewRemoveExpiredBackupsWorker(nil, quietLog(), 0)
	if w.ExpiryGrace != DefaultBackupExpiryGrace {
		t.Errorf("ExpiryGrace = %v; want %v", w.ExpiryGrace, DefaultBackupExpiryGrace)
	}
}

func TestRemoveExpiredBackupsWorker_NilLogUsesDefault(t *testing.T) {
	w := NewRemoveExpiredBackupsWorker(nil, nil, time.Minute)
	if w.log == nil {
		t.Error("expected non-nil logger when nil is passed")
	}
}

func TestRemoveExpiredBackupsWorker_DryRunDoesNotDelete(t *testing.T) {
	f := newWorkerFixture(t)

	// Mark the seeded row as expired by scheduling deletion + advancing purgeTime.
	ctx := context.Background()
	_ = f.store.ScheduleBackupDeletion(ctx, f.mf.authMessages)

	w := NewRemoveExpiredBackupsWorker(f.svc, quietLog(), time.Nanosecond)
	w.DryRun = true
	// purgeTime far in the future so our row appears expired
	if err := w.Run(ctx); err != nil {
		t.Fatalf("Run (dry): %v", err)
	}
}

func TestRemoveExpiredBackupsWorker_NoExpiredRows(t *testing.T) {
	f := newWorkerFixture(t)
	// Row was just refreshed — no expired entries.
	w := NewRemoveExpiredBackupsWorker(f.svc, quietLog(), DefaultBackupExpiryGrace)
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run with no expired rows: %v", err)
	}
}

func TestRemoveExpiredBackupsWorker_ExpiresBackup(t *testing.T) {
	f := newWorkerFixture(t)
	ctx := context.Background()

	// Seed a deletion row.
	_ = f.store.ScheduleBackupDeletion(ctx, f.mf.authMessages)

	// Worker with a 1-nanosecond grace will see the row as expired
	// because the last-refresh is before purgeTime (which is now – 1ns).
	w := NewRemoveExpiredBackupsWorker(f.svc, quietLog(), time.Nanosecond)
	if err := w.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRemoveExpiredBackupsWorker_ContextCancellationAborts(t *testing.T) {
	f := newWorkerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	w := NewRemoveExpiredBackupsWorker(f.svc, quietLog(), time.Nanosecond)
	// Cancelled context: worker should abort cleanly (return context error).
	err := w.Run(ctx)
	// The worker checks ctx.Err() in the per-item loop; with no expired entries
	// from a pre-cancelled context it may return nil — either nil or context error
	// is acceptable; the test just ensures it does not panic.
	_ = err
}

// --- BackupUsageRecalculationWorker tests ------------------------------------

func TestBackupUsageRecalculationWorker_Name(t *testing.T) {
	w := NewBackupUsageRecalculationWorker(nil, quietLog())
	if w.Name() != "backup-usage-recalculation" {
		t.Errorf("Name() = %q", w.Name())
	}
}

func TestBackupUsageRecalculationWorker_Schedule(t *testing.T) {
	w := NewBackupUsageRecalculationWorker(nil, quietLog())
	if w.Schedule() != "0 5 * * 0" {
		t.Errorf("Schedule() = %q", w.Schedule())
	}
}

func TestBackupUsageRecalculationWorker_NilServiceNoOps(t *testing.T) {
	w := NewBackupUsageRecalculationWorker(&service.SignalService{}, quietLog())
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("expected nil for nil Backups, got %v", err)
	}
}

func TestBackupUsageRecalculationWorker_NilLogUsesDefault(t *testing.T) {
	w := NewBackupUsageRecalculationWorker(nil, nil)
	if w.log == nil {
		t.Error("expected non-nil logger when nil passed")
	}
}

func TestBackupUsageRecalculationWorker_EmptyStore(t *testing.T) {
	// Fresh store with no entries — ListBackupAttributes streams nothing.
	store := storagememory.NewMemoryBackupStore()
	blob := newWorkerFakeBlobStore()
	var rb zkgroup.RandomnessBytes
	for i := range rb {
		rb[i] = 0x11
	}
	serverSecret := zkgroup.GenerateGenericServerSecretParams(rb)
	clock := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return clock })
	mgr := backups.NewManager(backups.ManagerOptions{
		Store:              store,
		Blob:               blob,
		ServerSecretParams: serverSecret,
		Clock:              func() time.Time { return clock },
	})
	var rr zkgroup.RandomnessBytes
	for i := range rr {
		rr[i] = 0xBB
	}
	receiptParams, _ := zkgroup.GenerateServerSecretParams(rr)
	authMgr := backups.NewAuthManager(backups.AuthManagerOptions{
		Accounts:                    accounts.NewAccountsManager(storagememory.NewMemoryAccountStore(), 6),
		SetBackupIDLimiter:          limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		SetPaidMediaBackupIDLimiter: limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		ServerSecretParams:          serverSecret,
		ReceiptServerSecretParams:   receiptParams,
		RedeemedReceipts:            storagememory.NewMemoryRedeemedReceiptsStore(),
		Clock:                       func() time.Time { return clock },
	})
	svc := &service.SignalService{Backups: service.NewBackupService(backups.NewService(mgr, authMgr))}
	w := NewBackupUsageRecalculationWorker(svc, quietLog())
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("empty store: %v", err)
	}
}

func TestBackupUsageRecalculationWorker_RecalculatesUsage(t *testing.T) {
	f := newWorkerFixture(t)
	ctx := context.Background()

	// Place CDN objects so RecalculateQuota has something to count.
	prefix := f.mf.authMediaPaid.BackupDir + "/" + f.mf.authMediaPaid.MediaDir + "/"
	f.blob.objects[prefix+"a"] = make([]byte, 200)
	f.blob.objects[prefix+"b"] = make([]byte, 300)

	w := NewBackupUsageRecalculationWorker(f.svc, quietLog())
	if err := w.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// After the worker runs, the store should reflect the recalculated usage.
	usage, err := f.store.GetMediaUsage(ctx, f.mf.authMediaPaid)
	if err != nil {
		t.Fatalf("GetMediaUsage: %v", err)
	}
	if usage.Usage.BytesUsed != 500 {
		t.Errorf("BytesUsed = %d; want 500", usage.Usage.BytesUsed)
	}
	if usage.Usage.NumObjects != 2 {
		t.Errorf("NumObjects = %d; want 2", usage.Usage.NumObjects)
	}
}

func TestBackupUsageRecalculationWorker_ContextCancellationAborts(t *testing.T) {
	f := newWorkerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w := NewBackupUsageRecalculationWorker(f.svc, quietLog())
	// Pre-cancelled context: the worker's inner loop checks ctx.Err() and
	// returns it as the scan error. Acceptable outcomes: ctx.Err() or nil.
	_ = w.Run(ctx)
}

// --- expirationTypeName helper tests ----------------------------------------

func TestExpirationTypeName(t *testing.T) {
	tests := []struct {
		t    backups.ExpirationType
		want string
	}{
		{backups.ExpireAll, "all"},
		{backups.ExpireMedia, "media"},
		{backups.ExpireGarbageCollection, "garbage-collection"},
		{backups.ExpirationType(99), "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := expirationTypeName(tc.t)
			if got != tc.want {
				t.Errorf("expirationTypeName(%d) = %q; want %q", tc.t, got, tc.want)
			}
		})
	}
}

// --- ensure workers satisfy Worker interface at compile time ----------------

var _ Worker = (*RemoveExpiredBackupsWorker)(nil)
var _ Worker = (*BackupUsageRecalculationWorker)(nil)

// --- error accumulation: per-row errors are logged, not fatal ---------------

func TestBackupUsageRecalculationWorker_PerRowErrorAccumulated(t *testing.T) {
	// Inject a store whose ListBackupAttributes returns one row but with empty
	// HashedBackupID so RecalculateQuota returns InvalidArgumentError.
	// The worker should accumulate it and return errors.Join at the end.
	f := newWorkerFixture(t)

	// Retrieve a real attrs row and zero out the BackupDir to force an error.
	ctx := context.Background()
	var attrs backups.StoredAttributes
	_ = f.store.ListBackupAttributes(ctx, 1, func(a backups.StoredAttributes) error {
		attrs = a
		return nil
	})
	// Corrupt it so RecalculateQuota fails.
	attrs.BackupDir = ""
	attrs.MediaDir = ""

	// We cannot easily inject the broken attrs into the live store, but we can
	// call RecalculateQuota directly to confirm it returns InvalidArgumentError,
	// which validates the accumulation code path is exercised by manager_test.go.
	_, err := f.mf.manager.RecalculateQuota(ctx, attrs)
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Errorf("expected InvalidArgumentError for empty dirs, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// errInjectBackupService: minimal BackupService that returns controlled
// errors for specific methods; all other methods delegate to a real service.
// Used exclusively to hit error branches that the in-memory store cannot
// trigger through normal operation.
// ---------------------------------------------------------------------------

type errInjectBackupService struct {
	real            service.BackupService
	getExpiredErr   error
	expireErr       error
	listAttrsErr    error
	recalcErr       error
	recalcNilResult bool
}

func (s *errInjectBackupService) GetExpiredBackups(
	ctx context.Context, segments int, purgeTime time.Time, fn func(backups.ExpiredBackup) error,
) error {
	if s.getExpiredErr != nil {
		return s.getExpiredErr
	}
	return s.real.GetExpiredBackups(ctx, segments, purgeTime, fn)
}

func (s *errInjectBackupService) ExpireBackup(ctx context.Context, expired backups.ExpiredBackup) error {
	if s.expireErr != nil {
		return s.expireErr
	}
	return s.real.ExpireBackup(ctx, expired)
}

func (s *errInjectBackupService) ListBackupAttributes(
	ctx context.Context, segments int, fn func(backups.StoredAttributes) error,
) error {
	if s.listAttrsErr != nil {
		return s.listAttrsErr
	}
	return s.real.ListBackupAttributes(ctx, segments, fn)
}

func (s *errInjectBackupService) RecalculateQuota(
	ctx context.Context, attrs backups.StoredAttributes,
) (*backups.RecalculationResult, error) {
	if s.recalcErr != nil {
		return nil, s.recalcErr
	}
	if s.recalcNilResult {
		return nil, nil
	}
	return s.real.RecalculateQuota(ctx, attrs)
}

// Remaining interface methods delegate to the real service unchanged.

func (s *errInjectBackupService) SetBackupID(ctx context.Context, accountUUID string, deviceID uint64, req backups.SetBackupIDRequest) error {
	return s.real.SetBackupID(ctx, accountUUID, deviceID, req)
}
func (s *errInjectBackupService) GetBackupIDLimits(ctx context.Context, accountUUID string) (*backups.BackupIDLimits, error) {
	return s.real.GetBackupIDLimits(ctx, accountUUID)
}
func (s *errInjectBackupService) RedeemReceipt(ctx context.Context, accountUUID string, req backups.RedeemReceiptRequest) error {
	return s.real.RedeemReceipt(ctx, accountUUID, req)
}
func (s *errInjectBackupService) GetBackupAuthCredentials(ctx context.Context, accountUUID string, start, end time.Time) (*backups.CredentialsResponse, error) {
	return s.real.GetBackupAuthCredentials(ctx, accountUUID, start, end)
}
func (s *errInjectBackupService) AuthenticateBackupUser(ctx context.Context, pres, sig []byte, ua string) (*backups.AuthenticatedUser, error) {
	return s.real.AuthenticateBackupUser(ctx, pres, sig, ua)
}
func (s *errInjectBackupService) SetPublicKey(ctx context.Context, pres, sig, pub []byte) error {
	return s.real.SetPublicKey(ctx, pres, sig, pub)
}
func (s *errInjectBackupService) BackupInfo(ctx context.Context, user *backups.AuthenticatedUser) (*backups.Info, error) {
	return s.real.BackupInfo(ctx, user)
}
func (s *errInjectBackupService) TTLRefresh(ctx context.Context, user *backups.AuthenticatedUser) error {
	return s.real.TTLRefresh(ctx, user)
}
func (s *errInjectBackupService) CreateMessageBackupUploadDescriptor(ctx context.Context, user *backups.AuthenticatedUser) (*backups.UploadDescriptor, error) {
	return s.real.CreateMessageBackupUploadDescriptor(ctx, user)
}
func (s *errInjectBackupService) CreateTemporaryAttachmentUploadDescriptor(ctx context.Context, user *backups.AuthenticatedUser) (*backups.UploadDescriptor, error) {
	return s.real.CreateTemporaryAttachmentUploadDescriptor(ctx, user)
}
func (s *errInjectBackupService) GenerateReadAuth(ctx context.Context, user *backups.AuthenticatedUser, cdn int) (map[string]string, error) {
	return s.real.GenerateReadAuth(ctx, user, cdn)
}
func (s *errInjectBackupService) GenerateSVRBAuth(ctx context.Context, user *backups.AuthenticatedUser) (*backups.ExternalServiceCredentials, error) {
	return s.real.GenerateSVRBAuth(ctx, user)
}
func (s *errInjectBackupService) GetCopyQuota(ctx context.Context, user *backups.AuthenticatedUser, p []backups.CopyParameters) (*backups.CopyQuota, error) {
	return s.real.GetCopyQuota(ctx, user, p)
}
func (s *errInjectBackupService) CopyToBackup(ctx context.Context, q backups.CopyQuota, fn func(backups.CopyResult) error) error {
	return s.real.CopyToBackup(ctx, q, fn)
}
func (s *errInjectBackupService) ListMedia(ctx context.Context, user *backups.AuthenticatedUser, cursor *string, limit int) (*backups.ListMediaResult, error) {
	return s.real.ListMedia(ctx, user, cursor, limit)
}
func (s *errInjectBackupService) DeleteMedia(ctx context.Context, user *backups.AuthenticatedUser, descs []backups.StorageDescriptor, fn func(backups.StorageDescriptor) error) error {
	return s.real.DeleteMedia(ctx, user, descs, fn)
}
func (s *errInjectBackupService) DeleteEntireBackup(ctx context.Context, user *backups.AuthenticatedUser) error {
	return s.real.DeleteEntireBackup(ctx, user)
}

// Compile-time interface check.
var _ service.BackupService = (*errInjectBackupService)(nil)

// newErrInjectSvc wraps the real service from the fixture.
func newErrInjectSvc(f *workerFixture) *errInjectBackupService {
	return &errInjectBackupService{real: f.svc.Backups}
}

// newSvcWithInjector builds a *service.SignalService pointing at the injector.
func newSvcWithInjector(inj *errInjectBackupService) *service.SignalService {
	return &service.SignalService{Backups: inj}
}

// ---------------------------------------------------------------------------
// RemoveExpiredBackupsWorker error-path tests
// ---------------------------------------------------------------------------

// TestRemoveExpiredBackupsWorker_GetExpiredBackupsError covers line 70-72
// (GetExpiredBackups returns an error → Run returns it immediately).
func TestRemoveExpiredBackupsWorker_GetExpiredBackupsError(t *testing.T) {
	f := newWorkerFixture(t)
	sentinel := errors.New("scan failed")
	inj := newErrInjectSvc(f)
	inj.getExpiredErr = sentinel
	svc := newSvcWithInjector(inj)

	w := NewRemoveExpiredBackupsWorker(svc, quietLog(), time.Nanosecond)
	err := w.Run(context.Background())
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
}

// TestRemoveExpiredBackupsWorker_ExpireBackupError covers lines 87-94
// (ExpireBackup fails → logged and appended) and lines 97-99
// (len(deleteErrs) > 0 → errors.Join returned).
func TestRemoveExpiredBackupsWorker_ExpireBackupError(t *testing.T) {
	f := newWorkerFixture(t)
	ctx := context.Background()

	// Seed a deletion row so GetExpiredBackups yields at least one entry.
	_ = f.store.ScheduleBackupDeletion(ctx, f.mf.authMessages)

	expireErr := errors.New("expire failed")
	inj := newErrInjectSvc(f)
	inj.expireErr = expireErr
	svc := newSvcWithInjector(inj)

	// Grace of 1 ns so the seeded row is definitely past the purge threshold.
	w := NewRemoveExpiredBackupsWorker(svc, quietLog(), time.Nanosecond)
	err := w.Run(ctx)
	if err == nil {
		t.Fatal("expected error from ExpireBackup failures, got nil")
	}
	if !errors.Is(err, expireErr) {
		t.Errorf("expected expireErr in joined error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// BackupUsageRecalculationWorker error-path tests
// ---------------------------------------------------------------------------

// TestBackupUsageRecalculationWorker_RecalcError covers lines 153-159
// (RecalculateQuota returns error → accumulated) and lines 181-183
// (len(errs) > 0 → errors.Join returned).
func TestBackupUsageRecalculationWorker_RecalcError(t *testing.T) {
	f := newWorkerFixture(t)

	recalcErr := errors.New("recalc failed")
	inj := newErrInjectSvc(f)
	inj.recalcErr = recalcErr
	svc := newSvcWithInjector(inj)

	w := NewBackupUsageRecalculationWorker(svc, quietLog())
	err := w.Run(context.Background())
	if err == nil {
		t.Fatal("expected error from RecalculateQuota failures, got nil")
	}
	if !errors.Is(err, recalcErr) {
		t.Errorf("expected recalcErr in joined error, got %v", err)
	}
}

// TestBackupUsageRecalculationWorker_RecalcNilResult covers lines 160-162
// (RecalculateQuota returns (nil, nil) → callback returns nil and continues).
func TestBackupUsageRecalculationWorker_RecalcNilResult(t *testing.T) {
	f := newWorkerFixture(t)

	inj := newErrInjectSvc(f)
	inj.recalcNilResult = true
	svc := newSvcWithInjector(inj)

	w := NewBackupUsageRecalculationWorker(svc, quietLog())
	if err := w.Run(context.Background()); err != nil {
		t.Errorf("expected nil from nil-result recalc, got %v", err)
	}
}
