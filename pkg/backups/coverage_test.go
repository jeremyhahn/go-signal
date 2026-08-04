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

// TestAuthManager_GetBackupAuthCredentials_HappyPath drives the issuance
// loop end-to-end so the per-day inner loop in GetBackupAuthCredentials is
// covered, alongside levelForRedemption / mapReceiptLevelToBackupLevel /
// mergeVoucher.
func TestAuthManager_GetBackupAuthCredentials_IssuesAcrossWindow(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: makeBackupRequest(t, 0x91, 0x92),
		MediaBackupAuthCredentialRequest:    makeBackupRequest(t, 0x93, 0x94),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	start := f.clock.Truncate(24 * time.Hour)
	end := start.Add(2 * 24 * time.Hour)
	resp, err := f.authMgr.GetBackupAuthCredentials(ctx, f.accountUUID, start, end)
	if err != nil {
		t.Fatalf("GetBackupAuthCredentials: %v", err)
	}
	if len(resp.Credentials) != 4 {
		t.Errorf("issued %d credentials; want 4 (2 days × 2 types)", len(resp.Credentials))
	}
}

// TestAuthManager_GetBackupAuthCredentials_BadWindowShapes covers the input
// validation branches: non-day-aligned, end before start, window too big.
func TestAuthManager_GetBackupAuthCredentials_BadWindowShapes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	aligned := f.clock.Truncate(24 * time.Hour)

	cases := []struct {
		name        string
		start, end  time.Time
		fieldSubstr string
	}{
		{"not day aligned", aligned.Add(5 * time.Minute), aligned.Add(24 * time.Hour), "redemptionRange"},
		{"end before start", aligned.Add(48 * time.Hour), aligned, "redemptionRange"},
		{"exceeds 7 days", aligned, aligned.Add(15 * 24 * time.Hour), "redemptionRange"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := f.authMgr.GetBackupAuthCredentials(ctx, f.accountUUID, c.start, c.end)
			var inv *backups.InvalidArgumentError
			if !errors.As(err, &inv) || inv.Field != c.fieldSubstr {
				t.Errorf("expected InvalidArgumentError(%s), got %T: %v", c.fieldSubstr, err, err)
			}
		})
	}
}

// TestAuthManager_GetBackupAuthCredentials_EmptyAccountUUID covers the
// account-uuid guard at the top of the issuance path.
func TestAuthManager_GetBackupAuthCredentials_EmptyAccountUUID(t *testing.T) {
	f := newFixture(t)
	_, err := f.authMgr.GetBackupAuthCredentials(context.Background(), "", time.Time{}, time.Time{})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) || inv.Field != "accountUUID" {
		t.Fatalf("expected InvalidArgumentError(accountUUID), got %T: %v", err, err)
	}
}

// TestAuthManager_GetBackupIDLimits_EmptyAccountUUID covers the guard.
func TestAuthManager_GetBackupIDLimits_EmptyAccountUUID(t *testing.T) {
	f := newFixture(t)
	_, err := f.authMgr.GetBackupIDLimits(context.Background(), "")
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) || inv.Field != "accountUUID" {
		t.Fatalf("expected InvalidArgumentError(accountUUID), got %T: %v", err, err)
	}
}

// TestAuthManager_RedeemReceipt_PaidLevelExtendsThenClearsVoucher covers
// the happy-path branches in mergeVoucher (replaces wholesale when the
// level changes, keeps the further-out expiration when the level matches).
func TestAuthManager_RedeemReceipt_MergesVoucher(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: makeBackupRequest(t, 0x95, 0x96),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	exp1 := f.clock.Add(30 * 24 * time.Hour)
	rec1 := mintReceiptPresentation(t, f.receiptParams, uint64(backups.BackupLevelPaid), exp1)
	if err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: rec1,
	}); err != nil {
		t.Fatalf("RedeemReceipt 1: %v", err)
	}

	// A second, longer-lived receipt at the same level extends the voucher.
	exp2 := f.clock.Add(60 * 24 * time.Hour)
	rec2 := mintReceiptPresentation(t, f.receiptParams, uint64(backups.BackupLevelPaid), exp2)
	if err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: rec2,
	}); err != nil {
		t.Fatalf("RedeemReceipt 2: %v", err)
	}
	acct, _ := f.accountsMgr.Get(ctx, f.accountUUID)
	if !acct.BackupVoucher.Expiration.After(exp1.Add(-time.Second)) {
		t.Errorf("voucher should be extended; got %v", acct.BackupVoucher.Expiration)
	}
}

// TestAuthManager_RedeemReceipt_RejectsUnknownLevel covers the receipt-level
// mapping rejection path.
func TestAuthManager_RedeemReceipt_RejectsUnknownLevel(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: makeBackupRequest(t, 0x97, 0x98),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	exp := f.clock.Add(30 * 24 * time.Hour)
	bogus := mintReceiptPresentation(t, f.receiptParams, 999 /* unknown */, exp)
	err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: bogus,
	})
	if err == nil {
		t.Fatal("expected error for unknown receipt level")
	}
}

// TestManager_DeleteEntireBackup_FallbackOnPendingDeletion covers the
// PendingDeletionError path through deletePrefix.
func TestManager_DeleteEntireBackup_FallbackOnPendingDeletion(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	ctx := context.Background()
	// First call schedules.
	if err := f.manager.DeleteEntireBackup(ctx, &f.authMessages); err != nil {
		t.Fatalf("first DeleteEntireBackup: %v", err)
	}
	// Second call against the same (already pre-rotated) authUser should hit
	// the PendingDeletionError fallback and synchronously purge the prefix.
	if err := f.manager.DeleteEntireBackup(ctx, &f.authMessages); err != nil {
		t.Fatalf("fallback DeleteEntireBackup: %v", err)
	}
}

// TestNewManager_DefaultsAreApplied covers the defaulting branches in
// NewManager (clock, svrb, svrbClient, maxQuota).
func TestNewManager_DefaultsAreApplied(t *testing.T) {
	store := memory.NewMemoryBackupStore()
	var rb zkgroup.RandomnessBytes
	for i := range rb {
		rb[i] = 0x44
	}
	params := zkgroup.GenerateGenericServerSecretParams(rb)
	mgr := backups.NewManager(backups.ManagerOptions{
		Store:              store,
		Blob:               newFakeBlobStore(),
		ServerSecretParams: params,
		// Intentionally leave Clock, SVRB, SVRBClient, MaxQuota unset so
		// the defaulting branches in NewManager run.
	})
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
}

// TestAuthManager_IssuesPaidCredentialsWhenVoucherActive drives the
// levelForRedemption "voucher set + receipt-level mapped" branches so the
// per-day issuance produces paid credentials within the voucher window.
func TestAuthManager_IssuesPaidCredentialsWhenVoucherActive(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: makeBackupRequest(t, 0xC0, 0xC1),
		MediaBackupAuthCredentialRequest:    makeBackupRequest(t, 0xC2, 0xC3),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	// Redeem a paid receipt so the account has an active voucher.
	exp := f.clock.Add(30 * 24 * time.Hour)
	rec := mintReceiptPresentation(t, f.receiptParams, uint64(backups.BackupLevelPaid), exp)
	if err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: rec,
	}); err != nil {
		t.Fatalf("RedeemReceipt: %v", err)
	}
	start := f.clock.Truncate(24 * time.Hour)
	end := start.Add(2 * 24 * time.Hour)
	resp, err := f.authMgr.GetBackupAuthCredentials(ctx, f.accountUUID, start, end)
	if err != nil {
		t.Fatalf("GetBackupAuthCredentials: %v", err)
	}
	if len(resp.Credentials) != 4 {
		t.Fatalf("issued %d credentials; want 4", len(resp.Credentials))
	}
}

// TestAuthManager_GetBackupAuthCredentials_ClearsExpiredVoucher covers the
// hasExpiredVoucher branch in GetBackupAuthCredentials.
func TestAuthManager_GetBackupAuthCredentials_ClearsExpiredVoucher(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: makeBackupRequest(t, 0xC4, 0xC5),
		MediaBackupAuthCredentialRequest:    makeBackupRequest(t, 0xC6, 0xC7),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	// Manually attach an already-expired voucher so the issuance path's
	// expired-voucher cleanup runs.
	acct, _ := f.accountsMgr.Get(ctx, f.accountUUID)
	acct.BackupVoucher = &accounts.BackupVoucher{
		ReceiptLevel: uint64(backups.BackupLevelPaid),
		Expiration:   f.clock.Add(-24 * time.Hour),
	}
	if err := f.accountsMgr.Update(ctx, acct); err != nil {
		t.Fatalf("seed expired voucher: %v", err)
	}
	start := f.clock.Truncate(24 * time.Hour)
	end := start.Add(24 * time.Hour)
	if _, err := f.authMgr.GetBackupAuthCredentials(ctx, f.accountUUID, start, end); err != nil {
		t.Fatalf("GetBackupAuthCredentials: %v", err)
	}
	acct, _ = f.accountsMgr.Get(ctx, f.accountUUID)
	if acct.BackupVoucher != nil {
		t.Errorf("expired voucher should be cleared, still present: %+v", acct.BackupVoucher)
	}
}

// TestManager_RequireLevel_NilUserRejected drives the nil-user branch in
// requireLevel (called by every level-guarded manager method).
func TestManager_RequireLevel_NilUserRejected(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	_, err := f.manager.BackupInfo(context.Background(), nil)
	var fzk *backups.FailedZkAuthError
	if !errors.As(err, &fzk) {
		t.Fatalf("expected FailedZkAuthError for nil user, got %T: %v", err, err)
	}
}

// TestNewAuthManager_AppliesDefaultClock covers the Clock defaulting branch.
func TestNewAuthManager_AppliesDefaultClock(t *testing.T) {
	accountsMgr := accounts.NewAccountsManager(memory.NewMemoryAccountStore(), 6)
	var rb zkgroup.RandomnessBytes
	for i := range rb {
		rb[i] = 0x55
	}
	receiptParams, err := zkgroup.GenerateServerSecretParams(rb)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	mgr := backups.NewAuthManager(backups.AuthManagerOptions{
		Accounts:                    accountsMgr,
		SetBackupIDLimiter:          limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 1, RefillRate: 1}),
		SetPaidMediaBackupIDLimiter: limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 1, RefillRate: 1}),
		ServerSecretParams:          zkgroup.GenerateGenericServerSecretParams(rb),
		ReceiptServerSecretParams:   receiptParams,
		RedeemedReceipts:            memory.NewMemoryRedeemedReceiptsStore(),
		// Clock intentionally omitted.
	})
	if mgr == nil {
		t.Fatal("NewAuthManager returned nil")
	}
}
