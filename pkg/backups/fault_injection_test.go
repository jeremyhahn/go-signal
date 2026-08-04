package backups_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/backups"
)

// failingStore is a backups.Store decorator that lets tests force specific
// error returns from arbitrary methods. Unset hooks fall through to the
// wrapped backend.
type failingStore struct {
	inner                   backups.Store
	setPublicKeyErr         error
	retrieveAuthErr         error
	addMessageBackupErr     error
	ttlRefreshErr           error
	describeBackupErr       error
	trackMediaErr           error
	getMediaUsageErr        error
	setMediaUsageErr        error
	setMediaUsageForErr     error
	scheduleErr             error
	startExpirationErr      error
	finishExpirationErr     error
	listBackupAttributesErr error
	getExpiredBackupsErr    error
}

func (f *failingStore) SetPublicKey(ctx context.Context, id backups.BackupID, lvl backups.BackupLevel, pk []byte) error {
	if f.setPublicKeyErr != nil {
		return f.setPublicKeyErr
	}
	return f.inner.SetPublicKey(ctx, id, lvl, pk)
}
func (f *failingStore) RetrieveAuthenticationData(ctx context.Context, id backups.BackupID) (*backups.AuthenticationData, bool, error) {
	if f.retrieveAuthErr != nil {
		return nil, false, f.retrieveAuthErr
	}
	return f.inner.RetrieveAuthenticationData(ctx, id)
}
func (f *failingStore) AddMessageBackup(ctx context.Context, u backups.AuthenticatedUser) error {
	if f.addMessageBackupErr != nil {
		return f.addMessageBackupErr
	}
	return f.inner.AddMessageBackup(ctx, u)
}
func (f *failingStore) TTLRefresh(ctx context.Context, u backups.AuthenticatedUser) (*backups.StoredAttributes, error) {
	if f.ttlRefreshErr != nil {
		return nil, f.ttlRefreshErr
	}
	return f.inner.TTLRefresh(ctx, u)
}
func (f *failingStore) DescribeBackup(ctx context.Context, u backups.AuthenticatedUser) (*backups.Description, error) {
	if f.describeBackupErr != nil {
		return nil, f.describeBackupErr
	}
	return f.inner.DescribeBackup(ctx, u)
}
func (f *failingStore) TrackMedia(ctx context.Context, u backups.AuthenticatedUser, c, b int64) error {
	if f.trackMediaErr != nil {
		return f.trackMediaErr
	}
	return f.inner.TrackMedia(ctx, u, c, b)
}
func (f *failingStore) GetMediaUsage(ctx context.Context, u backups.AuthenticatedUser) (*backups.TimestampedUsageInfo, error) {
	if f.getMediaUsageErr != nil {
		return nil, f.getMediaUsageErr
	}
	return f.inner.GetMediaUsage(ctx, u)
}
func (f *failingStore) SetMediaUsage(ctx context.Context, u backups.AuthenticatedUser, usage backups.UsageInfo) error {
	if f.setMediaUsageErr != nil {
		return f.setMediaUsageErr
	}
	return f.inner.SetMediaUsage(ctx, u, usage)
}
func (f *failingStore) SetMediaUsageFor(ctx context.Context, a backups.StoredAttributes, usage backups.UsageInfo) error {
	if f.setMediaUsageForErr != nil {
		return f.setMediaUsageForErr
	}
	return f.inner.SetMediaUsageFor(ctx, a, usage)
}
func (f *failingStore) ScheduleBackupDeletion(ctx context.Context, u backups.AuthenticatedUser) error {
	if f.scheduleErr != nil {
		return f.scheduleErr
	}
	return f.inner.ScheduleBackupDeletion(ctx, u)
}
func (f *failingStore) StartExpiration(ctx context.Context, e backups.ExpiredBackup) error {
	if f.startExpirationErr != nil {
		return f.startExpirationErr
	}
	return f.inner.StartExpiration(ctx, e)
}
func (f *failingStore) FinishExpiration(ctx context.Context, e backups.ExpiredBackup) error {
	if f.finishExpirationErr != nil {
		return f.finishExpirationErr
	}
	return f.inner.FinishExpiration(ctx, e)
}
func (f *failingStore) ListBackupAttributes(ctx context.Context, seg int, fn func(backups.StoredAttributes) error) error {
	if f.listBackupAttributesErr != nil {
		return f.listBackupAttributesErr
	}
	return f.inner.ListBackupAttributes(ctx, seg, fn)
}
func (f *failingStore) GetExpiredBackups(ctx context.Context, seg int, t time.Time, fn func(backups.ExpiredBackup) error) error {
	if f.getExpiredBackupsErr != nil {
		return f.getExpiredBackupsErr
	}
	return f.inner.GetExpiredBackups(ctx, seg, t, fn)
}

var errInjected = errors.New("injected store failure")

// wrapped builds a managerFixture whose underlying store is wrapped with a
// failingStore decorator the test can mutate to force errors.
func newFaultFixture(t *testing.T) (*managerFixture, *failingStore) {
	mf := newManagerFixture(t, backups.BackupLevelPaid)
	fs := &failingStore{inner: mf.store}
	// Replace the manager with one whose Store is the wrapper.
	mf.manager = backups.NewManager(backups.ManagerOptions{
		Store:              fs,
		Blob:               mf.blob,
		ServerSecretParams: mf.serverSecret,
		Clock:              func() time.Time { return mf.clock },
	})
	return mf, fs
}

// --- Error-return paths ----------------------------------------------------

func TestManager_BackupInfo_PropagatesStoreError(t *testing.T) {
	mf, fs := newFaultFixture(t)
	fs.describeBackupErr = errInjected
	_, err := mf.manager.BackupInfo(context.Background(), &mf.authMessages)
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected error, got %v", err)
	}
}

func TestManager_TTLRefresh_PropagatesStoreError(t *testing.T) {
	mf, fs := newFaultFixture(t)
	fs.ttlRefreshErr = errInjected
	err := mf.manager.TTLRefresh(context.Background(), &mf.authMessages)
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected error, got %v", err)
	}
}

func TestManager_CreateMessageBackupUploadDescriptor_PropagatesStoreError(t *testing.T) {
	mf, fs := newFaultFixture(t)
	fs.addMessageBackupErr = errInjected
	_, err := mf.manager.CreateMessageBackupUploadDescriptor(context.Background(), &mf.authMessages)
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected error, got %v", err)
	}
}

func TestManager_GetCopyQuota_PropagatesGetMediaUsageError(t *testing.T) {
	mf, fs := newFaultFixture(t)
	fs.getMediaUsageErr = errInjected
	_, err := mf.manager.GetCopyQuota(context.Background(), &mf.authMediaPaid, []backups.CopyParameters{makeCopyParams(1, 100)})
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected error, got %v", err)
	}
}

func TestManager_GetCopyQuota_RecalcSetUsageErrorPropagates(t *testing.T) {
	mf, fs := newFaultFixture(t)
	// Force cached usage to max so recalc path runs; then make SetMediaUsage fail.
	_ = mf.store.SetMediaUsage(context.Background(), mf.authMediaPaid, backups.UsageInfo{
		BytesUsed: backups.DefaultMaxQuota, NumObjects: 1,
	})
	fs.setMediaUsageErr = errInjected
	_, err := mf.manager.GetCopyQuota(context.Background(), &mf.authMediaPaid, []backups.CopyParameters{makeCopyParams(2, 100)})
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected SetMediaUsage error, got %v", err)
	}
}

func TestManager_CopyToBackup_TrackMediaErrorAborts(t *testing.T) {
	mf, fs := newFaultFixture(t)
	fs.trackMediaErr = errInjected
	q := backups.CopyQuota{
		User:           mf.authMediaPaid,
		RequestsToCopy: []backups.CopyParameters{makeCopyParams(3, 100)},
	}
	err := mf.manager.CopyToBackup(context.Background(), q, func(backups.CopyResult) error { return nil })
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected error, got %v", err)
	}
}

func TestManager_CopyToBackup_CallbackErrorOnSuccessPropagates(t *testing.T) {
	mf := newManagerFixture(t, backups.BackupLevelPaid)
	q, _ := mf.manager.GetCopyQuota(context.Background(), &mf.authMediaPaid, []backups.CopyParameters{makeCopyParams(4, 100)})
	err := mf.manager.CopyToBackup(context.Background(), *q, func(backups.CopyResult) error { return errInjected })
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected callback error, got %v", err)
	}
}

func TestManager_ListMedia_PropagatesBlobError(t *testing.T) {
	mf := newManagerFixture(t, backups.BackupLevelPaid)
	// Construct an authenticated user with a 16-char dir so the list path
	// builds a valid prefix and we exercise decodeMediaIDFromCDN on bad input.
	prefix := mf.authMessages.BackupDir + "/" + mf.authMessages.MediaDir + "/"
	mf.blob.objects[prefix+"not_base64url!!"] = []byte("x")
	_, err := mf.manager.ListMedia(context.Background(), &mf.authMessages, nil, 10)
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidArgumentError on bad CDN key, got %T: %v", err, err)
	}
}

func TestManager_ExpireBackup_StartExpirationErrorAborts(t *testing.T) {
	mf, fs := newFaultFixture(t)
	fs.startExpirationErr = errInjected
	err := mf.manager.ExpireBackup(context.Background(), backups.ExpiredBackup{
		HashedBackupID: []byte("x"),
	})
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected error, got %v", err)
	}
}

func TestManager_RecalculateQuota_PropagatesStoreError(t *testing.T) {
	mf, fs := newFaultFixture(t)
	fs.setMediaUsageForErr = errInjected
	var attrs backups.StoredAttributes
	_ = mf.store.ListBackupAttributes(context.Background(), 1, func(a backups.StoredAttributes) error {
		attrs = a
		return nil
	})
	_, err := mf.manager.RecalculateQuota(context.Background(), attrs)
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected error, got %v", err)
	}
}

// TestManager_DeleteEntireBackup_ScheduleErrorPropagates covers the
// non-PendingDeletion error path in DeleteEntireBackup.
func TestManager_DeleteEntireBackup_ScheduleErrorPropagates(t *testing.T) {
	mf, fs := newFaultFixture(t)
	fs.scheduleErr = errInjected
	err := mf.manager.DeleteEntireBackup(context.Background(), &mf.authMessages)
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected error, got %v", err)
	}
}

// TestManager_ExpireBackup_RejectsInvalidPrefixLength covers the
// deletePrefix length-validation branch via the ExpireBackup wrapper.
func TestManager_ExpireBackup_RejectsInvalidPrefixLength(t *testing.T) {
	mf := newManagerFixture(t, backups.BackupLevelFree)
	err := mf.manager.ExpireBackup(context.Background(), backups.ExpiredBackup{
		HashedBackupID: []byte("x"),
		PrefixToDelete: "too-short",
	})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

// TestManager_AuthenticateBackupUser_StoreErrorPropagates ensures the
// RetrieveAuthenticationData error is surfaced.
func TestManager_AuthenticateBackupUser_StoreErrorPropagates(t *testing.T) {
	mf, fs := newFaultFixture(t)
	fs.retrieveAuthErr = errInjected
	pres := mf.mintPresentationBytes(t, backups.BackupLevelFree, backups.CredentialTypeMessages)
	sig := mf.signPresentation(t, pres)
	_, err := mf.manager.AuthenticateBackupUser(context.Background(), pres, sig, "")
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected error, got %v", err)
	}
}
