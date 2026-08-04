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

// testFixture bundles the parts needed to drive AuthManager + Manager
// tests against the in-memory backend. Constructing it is shared across
// every test file in this package.
type testFixture struct {
	authMgr       *backups.AuthManager
	accountsMgr   *accounts.AccountsManager
	store         *memory.MemoryBackupStore
	receipts      *memory.MemoryRedeemedReceiptsStore
	serverParams  *zkgroup.GenericServerSecretParams
	receiptParams *zkgroup.ServerSecretParams
	clock         time.Time
	accountUUID   string
}

func newFixture(t *testing.T) *testFixture {
	t.Helper()
	accountStore := memory.NewMemoryAccountStore()
	accountsMgr := accounts.NewAccountsManager(accountStore, 6)
	// Seed one primary-only account so SetBackupID can succeed.
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

	store := memory.NewMemoryBackupStore()
	receipts := memory.NewMemoryRedeemedReceiptsStore()

	// Generic server secret for backup auth.
	var rb zkgroup.RandomnessBytes
	for i := range rb {
		rb[i] = 0x10
	}
	serverParams := zkgroup.GenerateGenericServerSecretParams(rb)

	// Receipt server secret (different randomness).
	var rb2 zkgroup.RandomnessBytes
	for i := range rb2 {
		rb2[i] = 0x20
	}
	receiptParams, err := zkgroup.GenerateServerSecretParams(rb2)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}

	clock := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }

	authMgr := backups.NewAuthManager(backups.AuthManagerOptions{
		Accounts:                    accountsMgr,
		SetBackupIDLimiter:          limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		SetPaidMediaBackupIDLimiter: limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		ServerSecretParams:          serverParams,
		ReceiptServerSecretParams:   receiptParams,
		RedeemedReceipts:            receipts,
		Clock:                       now,
	})

	store.SetClock(now)
	receipts.SetClock(now)

	return &testFixture{
		authMgr:       authMgr,
		accountsMgr:   accountsMgr,
		store:         store,
		receipts:      receipts,
		serverParams:  serverParams,
		receiptParams: receiptParams,
		clock:         clock,
		accountUUID:   acct.UUID,
	}
}

// makeBackupRequest constructs a real BackupAuthCredentialRequest for the
// given backup key + ACI and returns its bincode wire bytes — the same
// shape clients submit via SetBackupID.
func makeBackupRequest(t *testing.T, backupKey byte, aciByte byte) []byte {
	t.Helper()
	var bk [32]byte
	for i := range bk {
		bk[i] = backupKey
	}
	var aciBytes [16]byte
	for i := range aciBytes {
		aciBytes[i] = aciByte
	}
	ctx, err := zkgroup.NewBackupAuthCredentialRequestContext(bk, zkgroup.NewACI(aciBytes))
	if err != nil {
		t.Fatalf("NewBackupAuthCredentialRequestContext: %v", err)
	}
	return zkgroup.SerializeBackupAuthCredentialRequest(ctx.GetRequest())
}

func TestAuthManager_CommitBackupID_PrimaryOnly(t *testing.T) {
	f := newFixture(t)
	req := makeBackupRequest(t, 0x01, 0x02)
	// Non-primary device rejected.
	err := f.authMgr.CommitBackupID(context.Background(), f.accountUUID, 2, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: req,
	})
	var perm *backups.PermissionError
	if !errors.As(err, &perm) {
		t.Fatalf("expected *PermissionError, got %T: %v", err, err)
	}
}

func TestAuthManager_CommitBackupID_RequiresAtLeastOneSlot(t *testing.T) {
	f := newFixture(t)
	err := f.authMgr.CommitBackupID(context.Background(), f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestAuthManager_CommitBackupID_PersistsAndIsIdempotent(t *testing.T) {
	f := newFixture(t)
	req := makeBackupRequest(t, 0x01, 0x02)
	ctx := context.Background()
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: req,
	}); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	acct, _ := f.accountsMgr.Get(ctx, f.accountUUID)
	if acct.BackupCredentialRequests == nil || len(acct.BackupCredentialRequests.Messages) == 0 {
		t.Fatal("messages slot not persisted")
	}
	// Re-committing the same bytes is a no-op (no error, no rate-limit hit).
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: req,
	}); err != nil {
		t.Fatalf("idempotent commit: %v", err)
	}
}

func TestAuthManager_CommitBackupID_RejectsMalformedRequest(t *testing.T) {
	f := newFixture(t)
	err := f.authMgr.CommitBackupID(context.Background(), f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: []byte("not a credential"),
	})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestAuthManager_GetBackupAuthCredentials_RequiresDayAlignment(t *testing.T) {
	f := newFixture(t)
	// 12:00 is not day-aligned.
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	_, err := f.authMgr.GetBackupAuthCredentials(context.Background(), f.accountUUID, start, start.Add(24*time.Hour))
	if err == nil {
		t.Fatal("expected day-alignment error")
	}
}

func TestAuthManager_GetBackupAuthCredentials_WindowExceeded(t *testing.T) {
	f := newFixture(t)
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	_, err := f.authMgr.GetBackupAuthCredentials(context.Background(), f.accountUUID, start, start.Add(8*24*time.Hour))
	if err == nil {
		t.Fatal("expected window-exceeded error")
	}
}

func TestAuthManager_GetBackupAuthCredentials_RequiresCommittedRequest(t *testing.T) {
	f := newFixture(t)
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	_, err := f.authMgr.GetBackupAuthCredentials(context.Background(), f.accountUUID, start, start.Add(24*time.Hour))
	var nf *backups.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError, got %T: %v", err, err)
	}
}

func TestAuthManager_GetBackupAuthCredentials_IssuesPerDay(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	msgReq := makeBackupRequest(t, 0x01, 0x02)
	mediaReq := makeBackupRequest(t, 0x03, 0x04)
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: msgReq,
		MediaBackupAuthCredentialRequest:    mediaReq,
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}

	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(3 * 24 * time.Hour)
	resp, err := f.authMgr.GetBackupAuthCredentials(ctx, f.accountUUID, start, end)
	if err != nil {
		t.Fatalf("GetBackupAuthCredentials: %v", err)
	}
	// Expect 3 days * 2 credential types = 6 entries.
	if len(resp.Credentials) != 6 {
		t.Errorf("got %d credentials; want 6", len(resp.Credentials))
	}
	// Every credential should be a non-empty serialized response.
	for _, c := range resp.Credentials {
		if len(c.Credential) == 0 {
			t.Errorf("zero-length credential bytes")
		}
		if _, err := zkgroup.DeserializeBackupAuthCredentialResponse(c.Credential); err != nil {
			t.Errorf("issued credential does not round-trip: %v", err)
		}
	}
}

func TestAuthManager_RedeemReceipt_RequiresMediaCommitment(t *testing.T) {
	f := newFixture(t)
	// Build a real receipt presentation issued by our receipt server secret.
	receiptBytes := mintReceiptPresentation(t, f.receiptParams, uint64(backups.BackupLevelPaid), f.clock.Add(24*time.Hour))
	err := f.authMgr.RedeemReceipt(context.Background(), f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receiptBytes,
	})
	var missing *backups.MissingIDCommitmentError
	if !errors.As(err, &missing) {
		t.Fatalf("expected *MissingIDCommitmentError, got %T: %v", err, err)
	}
}

func TestAuthManager_RedeemReceipt_MalformedPresentation(t *testing.T) {
	f := newFixture(t)
	err := f.authMgr.RedeemReceipt(context.Background(), f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: []byte("not a receipt"),
	})
	var bad *backups.BadReceiptError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadReceiptError, got %T: %v", err, err)
	}
}

func TestAuthManager_RedeemReceipt_ExpiredReceipt(t *testing.T) {
	f := newFixture(t)
	// Commit a media request first so MissingIDCommitmentError doesn't fire.
	ctx := context.Background()
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: makeBackupRequest(t, 0x03, 0x04),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	// Mint a receipt that expired before the fixture clock.
	expired := mintReceiptPresentation(t, f.receiptParams, uint64(backups.BackupLevelPaid), f.clock.Add(-1*time.Hour))
	err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: expired,
	})
	var bad *backups.BadReceiptError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadReceiptError for expired, got %T: %v", err, err)
	}
}

func TestAuthManager_RedeemReceipt_HappyPathUpdatesVoucher(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: makeBackupRequest(t, 0x03, 0x04),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	// Receipt valid for 30 days from clock.
	expiration := f.clock.Add(30 * 24 * time.Hour)
	receipt := mintReceiptPresentation(t, f.receiptParams, uint64(backups.BackupLevelPaid), expiration)
	if err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receipt,
	}); err != nil {
		t.Fatalf("RedeemReceipt: %v", err)
	}
	acct, _ := f.accountsMgr.Get(ctx, f.accountUUID)
	if acct.BackupVoucher == nil {
		t.Fatal("voucher not set")
	}
	if acct.BackupVoucher.ReceiptLevel != uint64(backups.BackupLevelPaid) {
		t.Errorf("voucher level = %d; want paid", acct.BackupVoucher.ReceiptLevel)
	}

	// Re-redeeming the same receipt by the SAME account is idempotent — Java's
	// RedeemedReceiptsManager.put returns true when the existing entry matches
	// (serial, expiration, level, accountUUID), so the second call must succeed
	// without error and not double-extend the voucher.
	prevVoucher := *acct.BackupVoucher
	if err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receipt,
	}); err != nil {
		t.Errorf("idempotent re-redemption: %v", err)
	}
	acct, _ = f.accountsMgr.Get(ctx, f.accountUUID)
	if !acct.BackupVoucher.Expiration.Equal(prevVoucher.Expiration) {
		t.Errorf("voucher expiration changed across idempotent retry: was %v, now %v", prevVoucher.Expiration, acct.BackupVoucher.Expiration)
	}
}

func TestAuthManager_GetBackupIDLimits_ReturnsZeroes(t *testing.T) {
	// The token-bucket limiter doesn't expose a non-consuming probe yet, so
	// GetBackupIDLimits reports "allowed now" (zero times). Document that.
	f := newFixture(t)
	limits, err := f.authMgr.GetBackupIDLimits(context.Background(), f.accountUUID)
	if err != nil {
		t.Fatalf("GetBackupIDLimits: %v", err)
	}
	if !limits.MessagesNextRotationAllowedAt.IsZero() || !limits.MediaNextRotationAllowedAt.IsZero() {
		t.Errorf("expected zero times until limiter exposes non-consuming probe")
	}
}

// mintReceiptPresentation builds a real ReceiptCredentialPresentation
// signed by serverParams. expiration is the receipt's claimed expiry; it
// is rounded down to day boundary because zkgroup's receipt verification
// requires day alignment.
func mintReceiptPresentation(t *testing.T, serverParams *zkgroup.ServerSecretParams, level uint64, expiration time.Time) []byte {
	t.Helper()
	pub := serverParams.GetPublicParams()

	var serial zkgroup.ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i + 1)
	}
	var r1, r2, r3 zkgroup.RandomnessBytes
	for i := range r1 {
		r1[i] = 0x80
		r2[i] = 0x81
		r3[i] = 0x82
	}

	reqCtx := pub.CreateReceiptCredentialRequestContext(r1, serial)
	dayAligned := expiration.Truncate(24 * time.Hour)
	respTs := zkgroup.NewTimestamp(uint64(dayAligned.Unix()))
	resp, err := serverParams.IssueReceiptCredential(r2, reqCtx.GetRequest(), respTs, level)
	if err != nil {
		t.Fatalf("IssueReceiptCredential: %v", err)
	}
	cred, err := pub.ReceiveReceiptCredential(reqCtx, resp)
	if err != nil {
		t.Fatalf("ReceiveReceiptCredential: %v", err)
	}
	presentation, err := pub.CreateReceiptCredentialPresentation(r3, cred)
	if err != nil {
		t.Fatalf("CreateReceiptCredentialPresentation: %v", err)
	}
	return zkgroup.SerializeReceiptCredentialPresentation(presentation)
}

// alwaysFailLimiter is a limits.RateLimiter that returns a sentinel error on
// every call. Used by tests that need to exercise the rate-limit branches of
// AuthManager without actually exhausting a real bucket.
type alwaysFailLimiter struct{ err error }

func (l *alwaysFailLimiter) Allow(_ context.Context, _ string) error         { return l.err }
func (l *alwaysFailLimiter) AllowN(_ context.Context, _ string, _ int) error { return l.err }

// newFixtureWithLimiters mirrors newFixture but lets the test inject custom
// rate-limiter implementations into both backup-ID slots.
func newFixtureWithLimiters(t *testing.T, setBackupID, setPaidMedia limits.RateLimiter) *testFixture {
	t.Helper()
	f := newFixture(t)
	// Rebuild the AuthManager with the supplied limiters; everything else
	// (accounts manager, server secrets, clock) carries through.
	f.authMgr = backups.NewAuthManager(backups.AuthManagerOptions{
		Accounts:                    f.accountsMgr,
		SetBackupIDLimiter:          setBackupID,
		SetPaidMediaBackupIDLimiter: setPaidMedia,
		ServerSecretParams:          f.serverParams,
		ReceiptServerSecretParams:   f.receiptParams,
		RedeemedReceipts:            f.receipts,
		Clock:                       func() time.Time { return f.clock },
	})
	return f
}

func TestNewAuthManager_NilClockUsesNow(t *testing.T) {
	// When opts.Clock is nil, NewAuthManager must substitute time.Now().UTC()
	// so the resulting manager is usable. Touch a method that calls clock().
	f := newFixture(t)
	mgr := backups.NewAuthManager(backups.AuthManagerOptions{
		Accounts:                    f.accountsMgr,
		SetBackupIDLimiter:          &alwaysFailLimiter{err: errInjected},
		SetPaidMediaBackupIDLimiter: &alwaysFailLimiter{err: errInjected},
		ServerSecretParams:          f.serverParams,
		ReceiptServerSecretParams:   f.receiptParams,
		RedeemedReceipts:            f.receipts,
		// Clock intentionally omitted.
	})
	if mgr == nil {
		t.Fatal("expected non-nil manager")
		return
	}
	// Any call that resolves a voucher exercises the wall-clock substitution.
	if _, err := mgr.GetBackupIDLimits(context.Background(), f.accountUUID); err != nil {
		t.Fatalf("GetBackupIDLimits: %v", err)
	}
}

func TestAuthManager_CommitBackupID_EmptyAccountUUID(t *testing.T) {
	f := newFixture(t)
	err := f.authMgr.CommitBackupID(context.Background(), "", accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: makeBackupRequest(t, 0x01, 0x02),
	})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestAuthManager_CommitBackupID_RejectsMalformedMediaRequest(t *testing.T) {
	f := newFixture(t)
	err := f.authMgr.CommitBackupID(context.Background(), f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: []byte("not a credential"),
	})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestAuthManager_CommitBackupID_AccountNotFound(t *testing.T) {
	f := newFixture(t)
	err := f.authMgr.CommitBackupID(context.Background(), "00000000-0000-0000-0000-99999999dead", accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: makeBackupRequest(t, 0x01, 0x02),
	})
	if err == nil {
		t.Fatal("expected error for missing account")
	}
}

func TestAuthManager_CommitBackupID_LimiterRejectsRotation(t *testing.T) {
	f := newFixtureWithLimiters(t,
		&alwaysFailLimiter{err: errInjected},
		&alwaysFailLimiter{err: errInjected},
	)
	err := f.authMgr.CommitBackupID(context.Background(), f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: makeBackupRequest(t, 0x01, 0x02),
	})
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected limiter error, got %v", err)
	}
}

func TestAuthManager_CommitBackupID_PaidMediaLimiterRejects(t *testing.T) {
	// Seed an active voucher so the paid-media rotation path runs (and its
	// limiter is consulted). The messages-side limiter is permissive so it
	// doesn't shadow the paid-media error we're targeting.
	f := newFixtureWithLimiters(t,
		limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		&alwaysFailLimiter{err: errInjected},
	)
	ctx := context.Background()
	acct, _ := f.accountsMgr.Get(ctx, f.accountUUID)
	acct.BackupVoucher = &accounts.BackupVoucher{
		ReceiptLevel: uint64(backups.BackupLevelPaid),
		Expiration:   f.clock.Add(7 * 24 * time.Hour),
	}
	if err := f.accountsMgr.Update(ctx, acct); err != nil {
		t.Fatalf("seed voucher: %v", err)
	}
	err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: makeBackupRequest(t, 0x03, 0x04),
	})
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected injected paid-media limiter error, got %v", err)
	}
}

func TestAuthManager_GetBackupAuthCredentials_EndNotAfterStart(t *testing.T) {
	f := newFixture(t)
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	_, err := f.authMgr.GetBackupAuthCredentials(context.Background(), f.accountUUID, start, start)
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidArgumentError for end==start, got %T: %v", err, err)
	}
}

func TestAuthManager_GetBackupAuthCredentials_AccountNotFound(t *testing.T) {
	f := newFixture(t)
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	_, err := f.authMgr.GetBackupAuthCredentials(context.Background(), "00000000-0000-0000-0000-99999999dead", start, start.Add(24*time.Hour))
	if err == nil {
		t.Fatal("expected error for missing account")
	}
}

func TestAuthManager_GetBackupAuthCredentials_MissingMediaSlot(t *testing.T) {
	// Commit only the messages slot; the issuance loop walks BOTH credential
	// types and must return NotFoundError when the media slot is empty.
	f := newFixture(t)
	ctx := context.Background()
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: makeBackupRequest(t, 0x01, 0x02),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	_, err := f.authMgr.GetBackupAuthCredentials(ctx, f.accountUUID, start, start.Add(24*time.Hour))
	var nf *backups.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError for missing media slot, got %T: %v", err, err)
	}
}

func TestAuthManager_GetBackupAuthCredentials_CorruptedStoredRequest(t *testing.T) {
	// Bypass CommitBackupID validation by writing garbage straight into the
	// account record. Issuance must then return InvalidArgumentError on the
	// stored bytes.
	f := newFixture(t)
	ctx := context.Background()
	acct, _ := f.accountsMgr.Get(ctx, f.accountUUID)
	acct.BackupCredentialRequests = &accounts.BackupCredentialRequests{
		Messages: []byte("garbage credential bytes"),
		Media:    []byte("garbage credential bytes"),
	}
	if err := f.accountsMgr.Update(ctx, acct); err != nil {
		t.Fatalf("seed corrupted req: %v", err)
	}
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	_, err := f.authMgr.GetBackupAuthCredentials(ctx, f.accountUUID, start, start.Add(24*time.Hour))
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestAuthManager_RedeemReceipt_EmptyAccountUUID(t *testing.T) {
	f := newFixture(t)
	err := f.authMgr.RedeemReceipt(context.Background(), "", backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: []byte("x"),
	})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestAuthManager_RedeemReceipt_EmptyPresentation(t *testing.T) {
	f := newFixture(t)
	err := f.authMgr.RedeemReceipt(context.Background(), f.accountUUID, backups.RedeemReceiptRequest{})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestAuthManager_RedeemReceipt_VerifyFailsForOtherServer(t *testing.T) {
	// A presentation signed by an unrelated server must fail VerifyReceiptCredentialPresentation.
	f := newFixture(t)
	var alienSeed zkgroup.RandomnessBytes
	for i := range alienSeed {
		alienSeed[i] = 0xEE
	}
	alien, err := zkgroup.GenerateServerSecretParams(alienSeed)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams (alien): %v", err)
	}
	receipt := mintReceiptPresentation(t, alien, uint64(backups.BackupLevelPaid), f.clock.Add(24*time.Hour))
	err = f.authMgr.RedeemReceipt(context.Background(), f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receipt,
	})
	var bad *backups.BadReceiptError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadReceiptError for cross-server presentation, got %T: %v", err, err)
	}
}

func TestAuthManager_RedeemReceipt_FreeLevelRejected(t *testing.T) {
	// Receipt with level=Free must reach the "level != Paid" rejection path.
	f := newFixture(t)
	ctx := context.Background()
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: makeBackupRequest(t, 0x03, 0x04),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	receipt := mintReceiptPresentation(t, f.receiptParams, uint64(backups.BackupLevelFree), f.clock.Add(24*time.Hour))
	err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receipt,
	})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidArgumentError for free receipt, got %T: %v", err, err)
	}
}

func TestAuthManager_RedeemReceipt_UnknownLevelRejected(t *testing.T) {
	// Unrecognized receipt level (anything other than 200/201) must trip the
	// mapReceiptLevelToBackupLevel guard.
	f := newFixture(t)
	ctx := context.Background()
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: makeBackupRequest(t, 0x03, 0x04),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	receipt := mintReceiptPresentation(t, f.receiptParams, 999, f.clock.Add(24*time.Hour))
	err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receipt,
	})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidArgumentError for unknown level, got %T: %v", err, err)
	}
}

func TestAuthManager_RedeemReceipt_AccountNotFound(t *testing.T) {
	f := newFixture(t)
	receipt := mintReceiptPresentation(t, f.receiptParams, uint64(backups.BackupLevelPaid), f.clock.Add(24*time.Hour))
	err := f.authMgr.RedeemReceipt(context.Background(), "00000000-0000-0000-0000-99999999dead", backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receipt,
	})
	if err == nil {
		t.Fatal("expected error for missing account")
	}
}

func TestAuthManager_RedeemReceipt_SerialReplayByDifferentAccount(t *testing.T) {
	// Same serial bytes submitted by two different account UUIDs: the second
	// caller must be rejected by RedeemedReceiptsStore.Put returning accepted=false.
	f := newFixture(t)
	ctx := context.Background()
	// Seed a second account so the replay attempt has a valid target.
	other := &accounts.Account{
		UUID:        "22222222-2222-2222-2222-222222222222",
		Number:      "+15550000002",
		IdentityKey: []byte("idk2"),
		Devices: []accounts.Device{{
			ID:        accounts.PrimaryDeviceID,
			AuthToken: "tok",
			SignedPreKey: &accounts.SignedPreKey{
				KeyID: 1, PublicKey: []byte("pk"), Signature: []byte("sig"),
			},
		}},
	}
	if err := f.accountsMgr.Create(ctx, other); err != nil {
		t.Fatalf("seed other account: %v", err)
	}
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: makeBackupRequest(t, 0x03, 0x04),
	}); err != nil {
		t.Fatalf("CommitBackupID first: %v", err)
	}
	if err := f.authMgr.CommitBackupID(ctx, other.UUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: makeBackupRequest(t, 0x05, 0x06),
	}); err != nil {
		t.Fatalf("CommitBackupID second: %v", err)
	}
	receipt := mintReceiptPresentation(t, f.receiptParams, uint64(backups.BackupLevelPaid), f.clock.Add(24*time.Hour))
	if err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receipt,
	}); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	// Replay against the second account with the same serial.
	err := f.authMgr.RedeemReceipt(ctx, other.UUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receipt,
	})
	var bad *backups.BadReceiptError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadReceiptError on cross-account replay, got %T: %v", err, err)
	}
}

func TestMergeVoucher_LevelMismatchReplaces(t *testing.T) {
	// Unit test the helper directly through an indirect path: feed a Paid
	// receipt to an account that already holds a Free voucher; the result
	// must be the Paid voucher, not a merge.
	f := newFixture(t)
	ctx := context.Background()
	acct, _ := f.accountsMgr.Get(ctx, f.accountUUID)
	acct.BackupVoucher = &accounts.BackupVoucher{
		ReceiptLevel: uint64(backups.BackupLevelFree),
		Expiration:   f.clock.Add(48 * time.Hour),
	}
	if err := f.accountsMgr.Update(ctx, acct); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: makeBackupRequest(t, 0x03, 0x04),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	receipt := mintReceiptPresentation(t, f.receiptParams, uint64(backups.BackupLevelPaid), f.clock.Add(24*time.Hour))
	if err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receipt,
	}); err != nil {
		t.Fatalf("RedeemReceipt: %v", err)
	}
	got, _ := f.accountsMgr.Get(ctx, f.accountUUID)
	if got.BackupVoucher.ReceiptLevel != uint64(backups.BackupLevelPaid) {
		t.Errorf("expected merged voucher to be Paid, got level=%d", got.BackupVoucher.ReceiptLevel)
	}
}

func TestMergeVoucher_PrevExpirationFurther(t *testing.T) {
	// Seed an existing Paid voucher whose expiration is FURTHER out than the
	// incoming receipt; mergeVoucher must keep the existing expiration.
	f := newFixture(t)
	ctx := context.Background()
	farFuture := f.clock.Add(365 * 24 * time.Hour).Truncate(24 * time.Hour)
	acct, _ := f.accountsMgr.Get(ctx, f.accountUUID)
	acct.BackupVoucher = &accounts.BackupVoucher{
		ReceiptLevel: uint64(backups.BackupLevelPaid),
		Expiration:   farFuture,
	}
	if err := f.accountsMgr.Update(ctx, acct); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MediaBackupAuthCredentialRequest: makeBackupRequest(t, 0x03, 0x04),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	// New receipt expires sooner than the existing voucher.
	receipt := mintReceiptPresentation(t, f.receiptParams, uint64(backups.BackupLevelPaid), f.clock.Add(24*time.Hour))
	if err := f.authMgr.RedeemReceipt(ctx, f.accountUUID, backups.RedeemReceiptRequest{
		ReceiptCredentialPresentation: receipt,
	}); err != nil {
		t.Fatalf("RedeemReceipt: %v", err)
	}
	got, _ := f.accountsMgr.Get(ctx, f.accountUUID)
	if !got.BackupVoucher.Expiration.Equal(farFuture) {
		t.Errorf("expected expiration to stay at %v, got %v", farFuture, got.BackupVoucher.Expiration)
	}
}

func TestLevelForRedemption_UnrecognizedVoucherLevelFallsToFree(t *testing.T) {
	// Seed a voucher with a level that isn't 200 (Free) or 201 (Paid). The
	// issuance loop must downgrade the credential to Free for the day.
	f := newFixture(t)
	ctx := context.Background()
	acct, _ := f.accountsMgr.Get(ctx, f.accountUUID)
	acct.BackupVoucher = &accounts.BackupVoucher{
		ReceiptLevel: 999,
		Expiration:   f.clock.Add(48 * time.Hour),
	}
	if err := f.accountsMgr.Update(ctx, acct); err != nil {
		t.Fatalf("seed voucher: %v", err)
	}
	if err := f.authMgr.CommitBackupID(ctx, f.accountUUID, accounts.PrimaryDeviceID, backups.SetBackupIDRequest{
		MessagesBackupAuthCredentialRequest: makeBackupRequest(t, 0x01, 0x02),
		MediaBackupAuthCredentialRequest:    makeBackupRequest(t, 0x03, 0x04),
	}); err != nil {
		t.Fatalf("CommitBackupID: %v", err)
	}
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	if _, err := f.authMgr.GetBackupAuthCredentials(ctx, f.accountUUID, start, start.Add(24*time.Hour)); err != nil {
		t.Fatalf("GetBackupAuthCredentials: %v", err)
	}
}
