package backups_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/backups"
	"github.com/jeremyhahn/go-signal/pkg/limits"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

// managerFixture wires a Manager against the in-memory store + fake blob
// store so individual tests can stay tight. The fixture seeds the user
// row (BackupDir / MediaDir) by calling SetPublicKey once with a known
// public key, which lets tests construct AuthenticatedUser values directly
// for methods other than SetPublicKey / AuthenticateBackupUser.
type managerFixture struct {
	manager       *backups.Manager
	store         *memory.MemoryBackupStore
	blob          *fakeBlobStore
	serverSecret  *zkgroup.GenericServerSecretParams
	clock         time.Time
	backupID      backups.BackupID
	identityKey   ecc.ECPrivateKeyable
	identityPub   []byte
	authMessages  backups.AuthenticatedUser
	authMediaPaid backups.AuthenticatedUser
	clientCtx     *zkgroup.BackupAuthCredentialRequestContext
}

func newManagerFixture(t *testing.T, level backups.BackupLevel) *managerFixture {
	t.Helper()

	store := memory.NewMemoryBackupStore()
	blob := newFakeBlobStore()

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

	// Seed the backup-id row with a real XEd25519 public key so subsequent
	// tests that hit the manager via AuthenticateBackupUser have a real
	// stored key to verify against.
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

	identityKeyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	publicKeyBytes := identityKeyPair.PublicKey().Serialize()

	ctx := context.Background()
	if err := store.SetPublicKey(ctx, backupID, level, publicKeyBytes); err != nil {
		t.Fatalf("seed SetPublicKey: %v", err)
	}
	data, ok, err := store.RetrieveAuthenticationData(ctx, backupID)
	if err != nil || !ok {
		t.Fatalf("RetrieveAuthenticationData: ok=%v err=%v", ok, err)
	}

	msgUser := backups.AuthenticatedUser{
		BackupID:       backupID,
		CredentialType: backups.CredentialTypeMessages,
		BackupLevel:    level,
		BackupDir:      data.BackupDir,
		MediaDir:       data.MediaDir,
		UserAgent:      "fixture",
	}
	mediaUser := msgUser
	mediaUser.CredentialType = backups.CredentialTypeMedia
	// authMediaPaid is always at the paid tier — tests that require a
	// downgraded media credential explicitly copy and overwrite.
	mediaUser.BackupLevel = backups.BackupLevelPaid

	return &managerFixture{
		manager:       mgr,
		store:         store,
		blob:          blob,
		serverSecret:  serverSecret,
		clock:         clock,
		backupID:      backupID,
		identityKey:   identityKeyPair.PrivateKey(),
		identityPub:   publicKeyBytes,
		authMessages:  msgUser,
		authMediaPaid: mediaUser,
		clientCtx:     reqCtx,
	}
}

// mintPresentationBytes creates the wire bytes of a freshly-minted backup-auth
// presentation for the fixture's backup-id at the fixture's clock time,
// with the supplied level and credential type.
func (f *managerFixture) mintPresentationBytes(t *testing.T, level backups.BackupLevel, credType backups.CredentialType) []byte {
	t.Helper()
	var r1, r2, r3 zkgroup.RandomnessBytes
	for i := range r1 {
		r1[i] = 0x10
		r2[i] = 0x20
		r3[i] = 0x30
	}
	day := zkgroup.NewTimestamp(uint64(f.clock.Truncate(24 * time.Hour).Unix()))
	req := f.clientCtx.GetRequest()
	resp, err := req.Issue(day, level, credType, f.serverSecret, r1)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cred, err := f.clientCtx.Receive(resp, f.serverSecret.GetPublicParams(), day)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	pres, err := cred.Present(f.serverSecret.GetPublicParams(), r2)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	_ = r3
	return zkgroup.SerializeBackupAuthCredentialPresentation(pres)
}

// signPresentation signs the presentation bytes with the fixture's
// XEd25519 identity key so AuthenticateBackupUser will verify.
func (f *managerFixture) signPresentation(t *testing.T, bytes []byte) []byte {
	t.Helper()
	sig, err := ecc.CalculateSignature(f.identityKey, bytes)
	if err != nil {
		t.Fatalf("CalculateSignature: %v", err)
	}
	return sig[:]
}

// --- SetPublicKey ----------------------------------------------------------

func TestManager_SetPublicKey_RejectsShortSignature(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	err := f.manager.SetPublicKey(context.Background(), []byte{0x00}, []byte("short"), []byte{0x05, 0x06})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) || inv.Field != "signature" {
		t.Fatalf("expected InvalidArgumentError(signature), got %T: %v", err, err)
	}
}

func TestManager_SetPublicKey_RejectsEmptyPublicKey(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	err := f.manager.SetPublicKey(context.Background(), []byte{0x00}, make([]byte, 64), nil)
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) || inv.Field != "publicKey" {
		t.Fatalf("expected InvalidArgumentError(publicKey), got %T: %v", err, err)
	}
}

func TestManager_SetPublicKey_RejectsMalformedPresentation(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	err := f.manager.SetPublicKey(context.Background(), []byte("garbage"), make([]byte, 64), f.identityPub)
	var fzk *backups.FailedZkAuthError
	if !errors.As(err, &fzk) {
		t.Fatalf("expected FailedZkAuthError, got %T: %v", err, err)
	}
}

func TestManager_SetPublicKey_HappyPath(t *testing.T) {
	store := memory.NewMemoryBackupStore()
	clock := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return clock })

	var rb zkgroup.RandomnessBytes
	for i := range rb {
		rb[i] = 0x77
	}
	serverSecret := zkgroup.GenerateGenericServerSecretParams(rb)

	mgr := backups.NewManager(backups.ManagerOptions{
		Store:              store,
		Blob:               newFakeBlobStore(),
		ServerSecretParams: serverSecret,
		Clock:              func() time.Time { return clock },
	})

	var backupKey [32]byte
	for i := range backupKey {
		backupKey[i] = 0xAA
	}
	var aciBytes [16]byte
	for i := range aciBytes {
		aciBytes[i] = 0xBB
	}
	reqCtx, err := zkgroup.NewBackupAuthCredentialRequestContext(backupKey, zkgroup.NewACI(aciBytes))
	if err != nil {
		t.Fatalf("NewBackupAuthCredentialRequestContext: %v", err)
	}
	day := zkgroup.NewTimestamp(uint64(clock.Truncate(24 * time.Hour).Unix()))
	resp, err := reqCtx.GetRequest().Issue(day, backups.BackupLevelFree, backups.CredentialTypeMessages, serverSecret, rb)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cred, err := reqCtx.Receive(resp, serverSecret.GetPublicParams(), day)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	pres, err := cred.Present(serverSecret.GetPublicParams(), rb)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	presBytes := zkgroup.SerializeBackupAuthCredentialPresentation(pres)

	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	sig, err := ecc.CalculateSignature(kp.PrivateKey(), presBytes)
	if err != nil {
		t.Fatalf("CalculateSignature: %v", err)
	}
	if err := mgr.SetPublicKey(context.Background(), presBytes, sig[:], kp.PublicKey().Serialize()); err != nil {
		t.Fatalf("SetPublicKey: %v", err)
	}
}

// --- AuthenticateBackupUser ------------------------------------------------

func TestManager_AuthenticateBackupUser_HappyPath(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	pres := f.mintPresentationBytes(t, backups.BackupLevelFree, backups.CredentialTypeMessages)
	sig := f.signPresentation(t, pres)
	user, err := f.manager.AuthenticateBackupUser(context.Background(), pres, sig, "ua/1")
	if err != nil {
		t.Fatalf("AuthenticateBackupUser: %v", err)
	}
	if user.BackupID != f.backupID {
		t.Errorf("BackupID mismatch")
	}
	if user.UserAgent != "ua/1" {
		t.Errorf("UserAgent = %q; want ua/1", user.UserAgent)
	}
}

func TestManager_AuthenticateBackupUser_BadSignature(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	pres := f.mintPresentationBytes(t, backups.BackupLevelFree, backups.CredentialTypeMessages)
	// 64-byte but wrong signature
	bogus := make([]byte, 64)
	_, err := f.manager.AuthenticateBackupUser(context.Background(), pres, bogus, "")
	var fzk *backups.FailedZkAuthError
	if !errors.As(err, &fzk) {
		t.Fatalf("expected FailedZkAuthError, got %T: %v", err, err)
	}
}

func TestManager_AuthenticateBackupUser_RejectsShortSignature(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	_, err := f.manager.AuthenticateBackupUser(context.Background(), []byte{0x00}, []byte("nope"), "")
	var fzk *backups.FailedZkAuthError
	if !errors.As(err, &fzk) {
		t.Fatalf("expected FailedZkAuthError, got %T: %v", err, err)
	}
}

func TestManager_AuthenticateBackupUser_NoPublicKeyRegistered(t *testing.T) {
	store := memory.NewMemoryBackupStore()
	clock := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return clock })
	var rb zkgroup.RandomnessBytes
	for i := range rb {
		rb[i] = 0x77
	}
	serverSecret := zkgroup.GenerateGenericServerSecretParams(rb)
	mgr := backups.NewManager(backups.ManagerOptions{
		Store:              store,
		Blob:               newFakeBlobStore(),
		ServerSecretParams: serverSecret,
		Clock:              func() time.Time { return clock },
	})

	var backupKey [32]byte
	for i := range backupKey {
		backupKey[i] = 0xC0
	}
	var aciBytes [16]byte
	reqCtx, _ := zkgroup.NewBackupAuthCredentialRequestContext(backupKey, zkgroup.NewACI(aciBytes))
	day := zkgroup.NewTimestamp(uint64(clock.Truncate(24 * time.Hour).Unix()))
	resp, _ := reqCtx.GetRequest().Issue(day, backups.BackupLevelFree, backups.CredentialTypeMessages, serverSecret, rb)
	cred, _ := reqCtx.Receive(resp, serverSecret.GetPublicParams(), day)
	pres, _ := cred.Present(serverSecret.GetPublicParams(), rb)
	presBytes := zkgroup.SerializeBackupAuthCredentialPresentation(pres)

	_, err := mgr.AuthenticateBackupUser(context.Background(), presBytes, make([]byte, 64), "")
	var fzk *backups.FailedZkAuthError
	if !errors.As(err, &fzk) || !strings.Contains(fzk.Reason, "no public key") {
		t.Fatalf("expected no-public-key error, got %T: %v", err, err)
	}
}

// --- BackupInfo / TTLRefresh ------------------------------------------------

func TestManager_BackupInfo_ReturnsAssembledInfo(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	_ = f.store.TrackMedia(context.Background(), f.authMediaPaid, 2, 250)
	info, err := f.manager.BackupInfo(context.Background(), &f.authMediaPaid)
	if err != nil {
		t.Fatalf("BackupInfo: %v", err)
	}
	if info.CDN != f.blob.CDNNumber() {
		t.Errorf("CDN = %d; want %d", info.CDN, f.blob.CDNNumber())
	}
	if info.BackupDir != f.authMediaPaid.BackupDir {
		t.Errorf("BackupDir mismatch")
	}
	if info.MessageBackupKey != backups.MessageBackupName {
		t.Errorf("MessageBackupKey = %q", info.MessageBackupKey)
	}
	if info.MediaUsedSpace == nil || *info.MediaUsedSpace != 250 {
		t.Errorf("MediaUsedSpace = %v; want 250", info.MediaUsedSpace)
	}
}

func TestManager_TTLRefresh_DelegatesToStore(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	if err := f.manager.TTLRefresh(context.Background(), &f.authMessages); err != nil {
		t.Fatalf("TTLRefresh: %v", err)
	}
}

// --- CreateMessageBackupUploadDescriptor -----------------------------------

func TestManager_CreateMessageBackupUploadDescriptor_HappyPath(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	desc, err := f.manager.CreateMessageBackupUploadDescriptor(context.Background(), &f.authMessages)
	if err != nil {
		t.Fatalf("CreateMessageBackupUploadDescriptor: %v", err)
	}
	if desc.CDN != f.blob.CDNNumber() {
		t.Errorf("CDN = %d", desc.CDN)
	}
	if !strings.HasSuffix(desc.Key, "/"+backups.MessageBackupName) {
		t.Errorf("Key = %q; want suffix /messageBackup", desc.Key)
	}
}

func TestManager_CreateMessageBackupUploadDescriptor_RejectsMediaCredential(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	_, err := f.manager.CreateMessageBackupUploadDescriptor(context.Background(), &f.authMediaPaid)
	var wrong *backups.WrongCredentialTypeError
	if !errors.As(err, &wrong) {
		t.Fatalf("expected WrongCredentialTypeError, got %T: %v", err, err)
	}
}

// --- CreateTemporaryAttachmentUploadDescriptor ----------------------------

func TestManager_CreateTemporaryAttachmentUploadDescriptor_HappyPath(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	desc, err := f.manager.CreateTemporaryAttachmentUploadDescriptor(context.Background(), &f.authMediaPaid)
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if desc.Key == "" {
		t.Error("expected random key")
	}
}

func TestManager_CreateTemporaryAttachmentUploadDescriptor_RequiresPaid(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	mediaFree := f.authMediaPaid
	mediaFree.BackupLevel = backups.BackupLevelFree
	_, err := f.manager.CreateTemporaryAttachmentUploadDescriptor(context.Background(), &mediaFree)
	var perm *backups.PermissionError
	if !errors.As(err, &perm) {
		t.Fatalf("expected PermissionError, got %T: %v", err, err)
	}
}

func TestManager_CreateTemporaryAttachmentUploadDescriptor_RequiresMediaCredential(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	msgPaid := f.authMessages
	msgPaid.BackupLevel = backups.BackupLevelPaid
	_, err := f.manager.CreateTemporaryAttachmentUploadDescriptor(context.Background(), &msgPaid)
	var wrong *backups.WrongCredentialTypeError
	if !errors.As(err, &wrong) {
		t.Fatalf("expected WrongCredentialTypeError, got %T: %v", err, err)
	}
}

// --- GenerateReadAuth / GenerateSVRBAuth ----------------------------------

func TestManager_GenerateReadAuth_RejectsUnsupportedCDN(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	_, err := f.manager.GenerateReadAuth(context.Background(), &f.authMessages, f.blob.CDNNumber()+99)
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestManager_GenerateReadAuth_HappyPath(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	headers, err := f.manager.GenerateReadAuth(context.Background(), &f.authMessages, f.blob.CDNNumber())
	if err != nil {
		t.Fatalf("GenerateReadAuth: %v", err)
	}
	if headers["Authorization"] == "" {
		t.Error("expected Authorization header from fake blob")
	}
}

func TestManager_GenerateSVRBAuth_DisabledByDefault(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	_, err := f.manager.GenerateSVRBAuth(context.Background(), &f.authMessages)
	if err == nil {
		t.Fatal("expected disabled SVRB error")
	}
}

func TestManager_GenerateSVRBAuth_RejectsMediaCredential(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	_, err := f.manager.GenerateSVRBAuth(context.Background(), &f.authMediaPaid)
	var wrong *backups.WrongCredentialTypeError
	if !errors.As(err, &wrong) {
		t.Fatalf("expected WrongCredentialTypeError, got %T: %v", err, err)
	}
}

// --- GetCopyQuota / CopyToBackup ------------------------------------------

func makeCopyParams(seed byte, srcLen int) backups.CopyParameters {
	mediaID := make([]byte, 32)
	for i := range mediaID {
		mediaID[i] = seed
	}
	return backups.CopyParameters{
		SourceCDN:    3,
		SourceKey:    "src-" + string([]byte{seed}),
		SourceLength: srcLen,
		EncryptionParameters: backups.MediaEncryptionParameters{
			EncryptionKey: make([]byte, 32),
			MACKey:        make([]byte, 32),
		},
		DestinationMediaID: mediaID,
	}
}

func TestManager_GetCopyQuota_AcceptsWithinQuota(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	q, err := f.manager.GetCopyQuota(context.Background(), &f.authMediaPaid, []backups.CopyParameters{
		makeCopyParams(0x01, 1000),
	})
	if err != nil {
		t.Fatalf("GetCopyQuota: %v", err)
	}
	if len(q.RequestsToCopy) != 1 || len(q.ToReject) != 0 {
		t.Errorf("split = %d/%d; want 1/0", len(q.RequestsToCopy), len(q.ToReject))
	}
}

func TestManager_GetCopyQuota_RecalculatesWhenCacheExhausted(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	// Force cached usage to the maximum so the manager has to recalculate
	// against the CDN before rejecting.
	_ = f.store.SetMediaUsage(context.Background(), f.authMediaPaid, backups.UsageInfo{
		BytesUsed:  backups.DefaultMaxQuota,
		NumObjects: 1,
	})
	q, err := f.manager.GetCopyQuota(context.Background(), &f.authMediaPaid, []backups.CopyParameters{
		makeCopyParams(0x02, 1000),
	})
	if err != nil {
		t.Fatalf("GetCopyQuota: %v", err)
	}
	if len(q.RequestsToCopy) != 1 {
		t.Errorf("expected recalc to allow the copy, split = %d/%d", len(q.RequestsToCopy), len(q.ToReject))
	}
}

func TestManager_GetCopyQuota_RejectsBadLength(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	bad := makeCopyParams(0x03, -1)
	_, err := f.manager.GetCopyQuota(context.Background(), &f.authMediaPaid, []backups.CopyParameters{bad})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestManager_CopyToBackup_SuccessFailureAndOutOfQuota(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	ctx := context.Background()

	ok := makeCopyParams(0x10, 100)
	missing := makeCopyParams(0x11, 100)
	rejected := makeCopyParams(0x12, 100)
	f.blob.copyFailFor[missing.SourceKey] = &backups.SourceNotFoundError{SourceKey: missing.SourceKey}

	quota := backups.CopyQuota{
		User:           f.authMediaPaid,
		RequestsToCopy: []backups.CopyParameters{ok, missing},
		ToReject:       []backups.CopyParameters{rejected},
	}
	var outcomes []backups.CopyOutcome
	err := f.manager.CopyToBackup(ctx, quota, func(r backups.CopyResult) error {
		outcomes = append(outcomes, r.Outcome)
		return nil
	})
	if err != nil {
		t.Fatalf("CopyToBackup: %v", err)
	}
	if len(outcomes) != 3 {
		t.Fatalf("outcomes = %v", outcomes)
	}
	if outcomes[0] != backups.CopyOutcomeSuccess {
		t.Errorf("outcome[0] = %d; want Success", outcomes[0])
	}
	if outcomes[1] != backups.CopyOutcomeSourceNotFound {
		t.Errorf("outcome[1] = %d; want SourceNotFound", outcomes[1])
	}
	if outcomes[2] != backups.CopyOutcomeOutOfQuota {
		t.Errorf("outcome[2] = %d; want OutOfQuota", outcomes[2])
	}
}

func TestManager_CopyToBackup_UnexpectedErrorRefundsAndAborts(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	ctx := context.Background()
	bad := makeCopyParams(0x20, 100)
	f.blob.copyFailFor[bad.SourceKey] = errFakeBlobCopy
	quota := backups.CopyQuota{
		User:           f.authMediaPaid,
		RequestsToCopy: []backups.CopyParameters{bad},
	}
	err := f.manager.CopyToBackup(ctx, quota, func(backups.CopyResult) error { return nil })
	if !errors.Is(err, errFakeBlobCopy) {
		t.Fatalf("expected errFakeBlobCopy, got %v", err)
	}
	usage, _ := f.store.GetMediaUsage(ctx, f.authMediaPaid)
	if usage.Usage.BytesUsed != 0 || usage.Usage.NumObjects != 0 {
		t.Errorf("refund failed: usage=%+v", usage.Usage)
	}
}

// --- ListMedia / DeleteMedia / DeleteEntireBackup -------------------------

func TestManager_ListMedia_DecodesKeysFromCDN(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	ctx := context.Background()
	q, err := f.manager.GetCopyQuota(ctx, &f.authMediaPaid, []backups.CopyParameters{
		makeCopyParams(0x30, 200),
		makeCopyParams(0x31, 200),
	})
	if err != nil {
		t.Fatalf("GetCopyQuota: %v", err)
	}
	if err := f.manager.CopyToBackup(ctx, *q, func(backups.CopyResult) error { return nil }); err != nil {
		t.Fatalf("CopyToBackup: %v", err)
	}

	listResult, err := f.manager.ListMedia(ctx, &f.authMessages, nil, 10)
	if err != nil {
		t.Fatalf("ListMedia: %v", err)
	}
	if len(listResult.Media) != 2 {
		t.Errorf("got %d media; want 2", len(listResult.Media))
	}
	for _, d := range listResult.Media {
		if d.CDN != f.blob.CDNNumber() {
			t.Errorf("CDN = %d", d.CDN)
		}
		if len(d.Key) != 32 {
			t.Errorf("decoded key len = %d; want 32", len(d.Key))
		}
	}
}

func TestManager_DeleteMedia_RejectsUnknownCDN(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	descs := []backups.StorageDescriptor{{CDN: f.blob.CDNNumber() + 99, Key: []byte("k")}}
	err := f.manager.DeleteMedia(context.Background(), &f.authMediaPaid, descs, func(backups.StorageDescriptor) error { return nil })
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestManager_DeleteMedia_RequiresMediaCredential(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	msgPaid := f.authMessages
	msgPaid.BackupLevel = backups.BackupLevelPaid
	err := f.manager.DeleteMedia(context.Background(), &msgPaid, nil, func(backups.StorageDescriptor) error { return nil })
	var wrong *backups.WrongCredentialTypeError
	if !errors.As(err, &wrong) {
		t.Fatalf("expected WrongCredentialTypeError, got %T: %v", err, err)
	}
}

func TestManager_DeleteMedia_HappyPathInvokesCallbackPerItem(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	ctx := context.Background()
	q, _ := f.manager.GetCopyQuota(ctx, &f.authMediaPaid, []backups.CopyParameters{
		makeCopyParams(0x40, 200),
		makeCopyParams(0x41, 200),
	})
	if err := f.manager.CopyToBackup(ctx, *q, func(backups.CopyResult) error { return nil }); err != nil {
		t.Fatalf("seed CopyToBackup: %v", err)
	}
	listResult, _ := f.manager.ListMedia(ctx, &f.authMessages, nil, 10)
	descs := make([]backups.StorageDescriptor, 0, len(listResult.Media))
	for _, m := range listResult.Media {
		descs = append(descs, backups.StorageDescriptor{CDN: m.CDN, Key: m.Key})
	}
	var seen int
	if err := f.manager.DeleteMedia(ctx, &f.authMediaPaid, descs, func(backups.StorageDescriptor) error {
		seen++
		return nil
	}); err != nil {
		t.Fatalf("DeleteMedia: %v", err)
	}
	if seen != len(descs) {
		t.Errorf("callback invoked %d times; want %d", seen, len(descs))
	}
}

func TestManager_DeleteEntireBackup_ReschedulesAndDeletes(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	if err := f.manager.DeleteEntireBackup(context.Background(), &f.authMessages); err != nil {
		t.Fatalf("DeleteEntireBackup: %v", err)
	}
	// After scheduling, the user's BackupDir/MediaDir are rotated in
	// store state; a subsequent retrieve should reflect this.
	data, ok, err := f.store.RetrieveAuthenticationData(context.Background(), f.backupID)
	if err != nil || !ok {
		t.Fatalf("retrieve after delete: ok=%v err=%v", ok, err)
	}
	if data.BackupDir == f.authMessages.BackupDir {
		t.Error("BackupDir should rotate after DeleteEntireBackup")
	}
}

// --- Worker-facing helpers ------------------------------------------------

func TestManager_ListBackupAttributes_StreamsAll(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	var count int
	err := f.manager.ListBackupAttributes(context.Background(), 1, func(attrs backups.StoredAttributes) error {
		count++
		if len(attrs.HashedBackupID) != 16 {
			t.Errorf("HashedBackupID len = %d", len(attrs.HashedBackupID))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ListBackupAttributes: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d; want 1", count)
	}
}

func TestManager_GetExpiredBackups_Delegates(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	// Newly-seeded row will not be expired; call should succeed with zero
	// callback invocations.
	var seen int
	err := f.manager.GetExpiredBackups(context.Background(), 1, f.clock.Add(-time.Hour), func(backups.ExpiredBackup) error {
		seen++
		return nil
	})
	if err != nil {
		t.Fatalf("GetExpiredBackups: %v", err)
	}
	if seen != 0 {
		t.Errorf("expected no expired rows, saw %d", seen)
	}
}

func TestManager_ExpireBackup_RoundTrip(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	ctx := context.Background()
	_ = f.store.ScheduleBackupDeletion(ctx, f.authMessages)
	var pending backups.ExpiredBackup
	_ = f.store.GetExpiredBackups(ctx, 1, time.Now().Add(time.Hour), func(e backups.ExpiredBackup) error {
		if e.ExpirationType == backups.ExpireGarbageCollection {
			pending = e
		}
		return nil
	})
	if len(pending.HashedBackupID) == 0 {
		t.Fatal("no pending row found")
	}
	if err := f.manager.ExpireBackup(ctx, pending); err != nil {
		t.Fatalf("ExpireBackup: %v", err)
	}
}

func TestManager_RecalculateQuota_UpdatesStoreUsage(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	ctx := context.Background()
	// Seed two real CDN objects so CalculateBytesUsed has something to count.
	prefix := f.authMediaPaid.BackupDir + "/" + f.authMediaPaid.MediaDir + "/"
	f.blob.objects[prefix+"a"] = make([]byte, 200)
	f.blob.objects[prefix+"b"] = make([]byte, 300)

	var attrs backups.StoredAttributes
	_ = f.store.ListBackupAttributes(ctx, 1, func(a backups.StoredAttributes) error {
		attrs = a
		return nil
	})

	res, err := f.manager.RecalculateQuota(ctx, attrs)
	if err != nil {
		t.Fatalf("RecalculateQuota: %v", err)
	}
	if res.NewUsage.NumObjects != 2 || res.NewUsage.BytesUsed != 500 {
		t.Errorf("new usage = %+v; want bytes=500 count=2", res.NewUsage)
	}
	usage, _ := f.store.GetMediaUsage(ctx, f.authMediaPaid)
	if usage.Usage.BytesUsed != 500 {
		t.Errorf("store usage not persisted: %+v", usage.Usage)
	}
}

func TestManager_RecalculateQuota_RejectsMissingDirs(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	_, err := f.manager.RecalculateQuota(context.Background(), backups.StoredAttributes{HashedBackupID: []byte("x")})
	var inv *backups.InvalidArgumentError
	if !errors.As(err, &inv) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

// --- requireLevel / requireCredentialType rejection paths -------------------
//
// Every paid-tier method must refuse a free-tier user, and every credential-
// type-bound method must refuse the wrong type. These tests exercise the
// guard branches at the top of each manager method in one place so the
// individual happy-path tests don't have to.

func TestManager_TTLRefresh_NilUserRejected(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	err := f.manager.TTLRefresh(context.Background(), nil)
	var fz *backups.FailedZkAuthError
	if !errors.As(err, &fz) {
		t.Fatalf("expected *FailedZkAuthError, got %T: %v", err, err)
	}
}

func TestManager_CreateMessageBackupUploadDescriptor_NilUserRejected(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	if _, err := f.manager.CreateMessageBackupUploadDescriptor(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil user")
	}
}

func TestManager_CreateTemporaryAttachmentUploadDescriptor_NilUserRejected(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	if _, err := f.manager.CreateTemporaryAttachmentUploadDescriptor(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil user")
	}
}

func TestManager_GenerateReadAuth_NilUserRejected(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	if _, err := f.manager.GenerateReadAuth(context.Background(), nil, f.blob.CDNNumber()); err == nil {
		t.Fatal("expected error for nil user")
	}
}

func TestManager_GenerateSVRBAuth_NilUserRejected(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	if _, err := f.manager.GenerateSVRBAuth(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil user")
	}
}

func TestManager_GenerateSVRBAuth_RequiresMessagesCredential(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	user := f.authMessages
	user.CredentialType = backups.CredentialTypeMedia
	_, err := f.manager.GenerateSVRBAuth(context.Background(), &user)
	var wrong *backups.WrongCredentialTypeError
	if !errors.As(err, &wrong) {
		t.Fatalf("expected *WrongCredentialTypeError, got %T: %v", err, err)
	}
}

func TestManager_GetCopyQuota_RequiresPaidLevel(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	user := f.authMessages
	user.BackupLevel = backups.BackupLevelFree
	user.CredentialType = backups.CredentialTypeMedia
	_, err := f.manager.GetCopyQuota(context.Background(), &user, []backups.CopyParameters{makeCopyParams(1, 100)})
	var perm *backups.PermissionError
	if !errors.As(err, &perm) {
		t.Fatalf("expected *PermissionError, got %T: %v", err, err)
	}
}

func TestManager_ListMedia_NilUserRejected(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	if _, err := f.manager.ListMedia(context.Background(), nil, nil, 10); err == nil {
		t.Fatal("expected error for nil user")
	}
}

func TestManager_DeleteMedia_RequiresMediaCredentialOnWrongType(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelPaid)
	user := f.authMessages
	user.CredentialType = backups.CredentialTypeMessages
	user.BackupLevel = backups.BackupLevelFree
	err := f.manager.DeleteMedia(
		context.Background(),
		&user,
		[]backups.StorageDescriptor{{CDN: f.blob.CDNNumber(), Key: []byte("aaaaaaaaaaaaaaaa")}},
		func(backups.StorageDescriptor) error { return nil },
	)
	var wrong *backups.WrongCredentialTypeError
	if !errors.As(err, &wrong) {
		t.Fatalf("expected *WrongCredentialTypeError, got %T: %v", err, err)
	}
}

func TestManager_DeleteEntireBackup_NilUserRejected(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	if err := f.manager.DeleteEntireBackup(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil user")
	}
}

func TestManager_BackupInfo_NilUserRejected(t *testing.T) {
	f := newManagerFixture(t, backups.BackupLevelFree)
	if _, err := f.manager.BackupInfo(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil user")
	}
}
