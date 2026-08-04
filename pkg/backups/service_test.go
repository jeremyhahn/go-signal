package backups_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/backups"
	"github.com/jeremyhahn/go-signal/pkg/limits"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

// newServiceFixture composes a real Manager + AuthManager behind a Service.
// Tests then drive each Service method to confirm the delegation contract.
// Underlying behavior is exercised by manager_test.go and auth_manager_test.go;
// service_test.go's job is to lock in the wiring.
func newServiceFixture(t *testing.T) (*backups.Service, *managerFixture, *accounts.AccountsManager, string) {
	t.Helper()

	mf := newManagerFixture(t, backups.BackupLevelPaid)

	accountStore := memory.NewMemoryAccountStore()
	accountsMgr := accounts.NewAccountsManager(accountStore, 6)
	acct := &accounts.Account{
		UUID:        "11111111-1111-1111-1111-111111111111",
		Number:      "+15550000001",
		IdentityKey: []byte("idk"),
		Devices: []accounts.Device{
			{
				ID:        accounts.PrimaryDeviceID,
				AuthToken: "tok",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte("pubkey-placeholder"),
					Signature: []byte("signature-placeholder"),
				},
			},
		},
	}
	if err := accountsMgr.Create(context.Background(), acct); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	var rb zkgroup.RandomnessBytes
	for i := range rb {
		rb[i] = 0x99
	}
	receiptParams, err := zkgroup.GenerateServerSecretParams(rb)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	authMgr := backups.NewAuthManager(backups.AuthManagerOptions{
		Accounts:                    accountsMgr,
		SetBackupIDLimiter:          limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		SetPaidMediaBackupIDLimiter: limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		ServerSecretParams:          mf.serverSecret,
		ReceiptServerSecretParams:   receiptParams,
		RedeemedReceipts:            memory.NewMemoryRedeemedReceiptsStore(),
		Clock:                       func() time.Time { return mf.clock },
	})
	svc := backups.NewService(mf.manager, authMgr)
	return svc, mf, accountsMgr, acct.UUID
}

func TestService_AccountAuthenticatedSurface_DelegatesToAuthManager(t *testing.T) {
	svc, _, _, accountUUID := newServiceFixture(t)
	ctx := context.Background()

	// SetBackupID requires at least one slot — driving the AuthManager.
	err := svc.SetBackupID(ctx, accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("SetBackupID empty: expected InvalidArgumentError, got %T: %v", err, err)
	}

	// GetBackupIDLimits succeeds for a brand-new account (zero timestamps).
	if _, err := svc.GetBackupIDLimits(ctx, accountUUID); err != nil {
		t.Fatalf("GetBackupIDLimits: %v", err)
	}

	// RedeemReceipt requires an actual presentation; empty is rejected.
	err = svc.RedeemReceipt(ctx, accountUUID, backups.RedeemReceiptRequest{})
	if !errors.As(err, &inv) {
		t.Fatalf("RedeemReceipt empty: expected InvalidArgumentError, got %T: %v", err, err)
	}

	// GetBackupAuthCredentials requires a committed request. Without one,
	// the underlying AuthManager returns InvalidArgumentError (no committed
	// credential request).
	start := time.Now().UTC().Truncate(24 * time.Hour)
	end := start.Add(24 * time.Hour)
	if _, err := svc.GetBackupAuthCredentials(ctx, accountUUID, start, end); err == nil {
		t.Fatal("GetBackupAuthCredentials without commitment should error")
	}
}

func TestService_ZKAuthenticatedSurface_DelegatesToManager(t *testing.T) {
	svc, mf, _, _ := newServiceFixture(t)
	ctx := context.Background()

	// AuthenticateBackupUser with a real presentation and signature.
	pres := mf.mintPresentationBytes(t, backups.BackupLevelFree, backups.CredentialTypeMessages)
	sig := mf.signPresentation(t, pres)
	user, err := svc.AuthenticateBackupUser(ctx, pres, sig, "svc")
	if err != nil {
		t.Fatalf("AuthenticateBackupUser: %v", err)
	}
	if user.BackupID != mf.backupID {
		t.Errorf("authenticated user BackupID mismatch")
	}

	// SetPublicKey rejects bad signature length up front — confirms wiring.
	err = svc.SetPublicKey(ctx, pres, []byte("short"), mf.identityPub)
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("SetPublicKey: %v", err)
	}

	// BackupInfo for the authenticated user.
	if _, err := svc.BackupInfo(ctx, &mf.authMessages); err != nil {
		t.Fatalf("BackupInfo: %v", err)
	}
	if err := svc.TTLRefresh(ctx, &mf.authMessages); err != nil {
		t.Fatalf("TTLRefresh: %v", err)
	}

	// Upload-descriptor methods.
	if _, err := svc.CreateMessageBackupUploadDescriptor(ctx, &mf.authMessages); err != nil {
		t.Fatalf("CreateMessageBackupUploadDescriptor: %v", err)
	}
	if _, err := svc.CreateTemporaryAttachmentUploadDescriptor(ctx, &mf.authMediaPaid); err != nil {
		t.Fatalf("CreateTemporaryAttachmentUploadDescriptor: %v", err)
	}

	// CDN read auth.
	if _, err := svc.GenerateReadAuth(ctx, &mf.authMessages, mf.blob.CDNNumber()); err != nil {
		t.Fatalf("GenerateReadAuth: %v", err)
	}

	// SVRBAuth — default disabled generator returns an error.
	if _, err := svc.GenerateSVRBAuth(ctx, &mf.authMessages); err == nil {
		t.Fatal("SVRBAuth default disabled should error")
	}
}

func TestService_MediaSurface_DelegatesToManager(t *testing.T) {
	svc, mf, _, _ := newServiceFixture(t)
	ctx := context.Background()

	// GetCopyQuota → CopyToBackup roundtrip.
	q, err := svc.GetCopyQuota(ctx, &mf.authMediaPaid, []backups.CopyParameters{
		makeCopyParams(0x50, 100),
	})
	if err != nil {
		t.Fatalf("GetCopyQuota: %v", err)
	}
	if err := svc.CopyToBackup(ctx, *q, func(backups.CopyResult) error { return nil }); err != nil {
		t.Fatalf("CopyToBackup: %v", err)
	}
	if _, err := svc.ListMedia(ctx, &mf.authMessages, nil, 10); err != nil {
		t.Fatalf("ListMedia: %v", err)
	}
	if err := svc.DeleteMedia(ctx, &mf.authMediaPaid, nil, func(backups.StorageDescriptor) error { return nil }); err != nil {
		t.Fatalf("DeleteMedia: %v", err)
	}
	if err := svc.DeleteEntireBackup(ctx, &mf.authMessages); err != nil {
		t.Fatalf("DeleteEntireBackup: %v", err)
	}
}

func TestService_WorkerSurface_DelegatesToManager(t *testing.T) {
	svc, mf, _, _ := newServiceFixture(t)
	ctx := context.Background()

	// ListBackupAttributes streams the seeded row.
	var attrs backups.StoredAttributes
	if err := svc.ListBackupAttributes(ctx, 1, func(a backups.StoredAttributes) error {
		attrs = a
		return nil
	}); err != nil {
		t.Fatalf("ListBackupAttributes: %v", err)
	}
	if len(attrs.HashedBackupID) == 0 {
		t.Fatal("expected at least one attribute row")
	}

	// GetExpiredBackups — no expired rows on a fresh fixture.
	if err := svc.GetExpiredBackups(ctx, 1, mf.clock.Add(-time.Hour), func(backups.ExpiredBackup) error {
		return nil
	}); err != nil {
		t.Fatalf("GetExpiredBackups: %v", err)
	}

	// RecalculateQuota — write some objects so the calculation has data.
	prefix := mf.authMediaPaid.BackupDir + "/" + mf.authMediaPaid.MediaDir + "/"
	mf.blob.objects[prefix+"a"] = make([]byte, 100)
	res, err := svc.RecalculateQuota(ctx, attrs)
	if err != nil {
		t.Fatalf("RecalculateQuota: %v", err)
	}
	if res.NewUsage.BytesUsed != 100 {
		t.Errorf("RecalculateQuota result = %+v; want bytes=100", res.NewUsage)
	}
}

func TestService_ExpireBackup_DelegatesToManager(t *testing.T) {
	svc, mf, _, _ := newServiceFixture(t)
	ctx := context.Background()
	// Queue a pending-deletion row by scheduling a backup deletion.
	_ = mf.store.ScheduleBackupDeletion(ctx, mf.authMessages)
	var pending backups.ExpiredBackup
	_ = mf.store.GetExpiredBackups(ctx, 1, time.Now().Add(time.Hour), func(e backups.ExpiredBackup) error {
		if e.ExpirationType == backups.ExpireGarbageCollection {
			pending = e
		}
		return nil
	})
	if len(pending.HashedBackupID) == 0 {
		t.Fatal("no pending row found")
	}
	if err := svc.ExpireBackup(ctx, pending); err != nil {
		t.Fatalf("ExpireBackup: %v", err)
	}
}
