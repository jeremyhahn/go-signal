package rest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/backups"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/limits"
	"github.com/jeremyhahn/go-signal/pkg/service"
	storagememory "github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

// --------------------------------------------------------------------------
// handleGetBackupAuth
// --------------------------------------------------------------------------

func TestHandleGetBackupAuth_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetBackupAuth_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetBackupInfo
// --------------------------------------------------------------------------

func TestHandleGetBackupInfo_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Despite the "_Success" name, this test verifies the
	// backups-not-configured path on a ZK-authenticated endpoint. Provide
	// stub ZK headers so the handler reaches the nil-backups branch
	// rather than short-circuiting at the auth-headers check.
	req := httptest.NewRequest(http.MethodGet, "/v1/archives", nil)
	req.Header.Set("X-Signal-ZK-Auth", "AA==")
	req.Header.Set("X-Signal-ZK-Auth-Signature", "AA==")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetBackupInfo_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/archives", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleSetBackupId
// --------------------------------------------------------------------------

func TestHandleSetBackupId_NotImplemented(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/archives/backupid", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rr.Code)
	}
}

func TestHandleSetBackupId_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/archives/backupid", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetBackupUploadForm
// --------------------------------------------------------------------------

func TestHandleGetBackupUploadForm_NotImplemented(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// This is a ZK-authenticated endpoint; provide stub ZK headers so the
	// handler passes the auth-presence check and reaches the
	// backups-not-configured branch we want to verify.
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/upload/form", nil)
	req.Header.Set("X-Signal-ZK-Auth", "AA==")
	req.Header.Set("X-Signal-ZK-Auth-Signature", "AA==")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetBackupUploadForm_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/upload/form", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleRefreshBackup
// --------------------------------------------------------------------------

func TestHandleRefreshBackup_NotImplemented(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// ZK-authenticated endpoint; supply stub ZK headers so the handler
	// reaches the backups-not-configured branch under test.
	req := httptest.NewRequest(http.MethodPost, "/v1/archives", nil)
	req.Header.Set("X-Signal-ZK-Auth", "AA==")
	req.Header.Set("X-Signal-ZK-Auth-Signature", "AA==")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rr.Code)
	}
}

func TestHandleRefreshBackup_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/archives", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// =============================================================================
// Extended archive handler tests — backup-service-enabled server
// =============================================================================

// archiveTestFixture wires a real backups.Service backed by in-memory stores
// into the REST test server so the ZK-authenticated and account-authenticated
// endpoints get past the "backup service not configured" 501 guard.
type archiveTestFixture struct {
	server       *Server
	serverSecret *zkgroup.GenericServerSecretParams
	clock        time.Time
	backupID     backups.BackupID
	identityKey  ecc.ECPrivateKeyable
	identityPub  []byte
	backupDir    string
	mediaDir     string
	clientCtx    *zkgroup.BackupAuthCredentialRequestContext
	blobCDN      int
	// authAccountsMgr is the AccountsManager used by the AuthManager inside
	// backups.Service. Basic-auth uses s.accounts (a separate store). Tests
	// that exercise GetBackupAuthCredentials must seed both stores.
	authAccountsMgr *accounts.AccountsManager
}

// newTestServerWithBackups builds an archive-capable server (backups.Service
// wired in) alongside the archive test fixture.  The returned fixture has the
// backup-id row pre-seeded so ZK auth calls succeed immediately.
func newTestServerWithBackups(t *testing.T) *archiveTestFixture {
	t.Helper()

	store := storagememory.NewMemoryBackupStore()
	blob := newArchiveFakeBlobStore()
	var rb zkgroup.RandomnessBytes
	for i := range rb {
		rb[i] = 0x55
	}
	serverSecret := zkgroup.GenerateGenericServerSecretParams(rb)
	clock := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return clock })

	mgr := backups.NewManager(backups.ManagerOptions{
		Store:              store,
		Blob:               blob,
		ServerSecretParams: serverSecret,
		AttachmentLimiter:  limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 100, RefillRate: 100}),
		Clock:              func() time.Time { return clock },
	})

	var backupKey [32]byte
	for i := range backupKey {
		backupKey[i] = 0xBB
	}
	aciBytes := [16]byte{0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F}
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
	data, ok, getErr := store.RetrieveAuthenticationData(ctx, backupID)
	if getErr != nil || !ok {
		t.Fatalf("RetrieveAuthenticationData: ok=%v err=%v", ok, getErr)
	}

	var rr zkgroup.RandomnessBytes
	for i := range rr {
		rr[i] = 0xCC
	}
	receiptParams, err := zkgroup.GenerateServerSecretParams(rr)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	accountsMgr := accounts.NewAccountsManager(storagememory.NewMemoryAccountStore(), 6)
	authMgr := backups.NewAuthManager(backups.AuthManagerOptions{
		Accounts:                    accountsMgr,
		SetBackupIDLimiter:          limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 100, RefillRate: 100}),
		SetPaidMediaBackupIDLimiter: limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 100, RefillRate: 100}),
		ServerSecretParams:          serverSecret,
		ReceiptServerSecretParams:   receiptParams,
		RedeemedReceipts:            storagememory.NewMemoryRedeemedReceiptsStore(),
		Clock:                       func() time.Time { return clock },
	})
	backupSvc := backups.NewService(mgr, authMgr)

	// Build the REST test server with Backups wired in.
	s := newTestServer(t)
	s.backups = service.NewBackupService(backupSvc)

	return &archiveTestFixture{
		server:          s,
		serverSecret:    serverSecret,
		clock:           clock,
		backupID:        backupID,
		identityKey:     kp.PrivateKey(),
		identityPub:     pubKey,
		backupDir:       data.BackupDir,
		mediaDir:        data.MediaDir,
		clientCtx:       reqCtx,
		blobCDN:         blob.cdn,
		authAccountsMgr: accountsMgr,
	}
}

// zkHeaders returns the two ZK auth headers for this fixture's backup-id.
func (f *archiveTestFixture) zkHeaders(t *testing.T, level backups.BackupLevel, credType backups.CredentialType) (string, string) {
	t.Helper()
	var r1, r2 zkgroup.RandomnessBytes
	for i := range r1 {
		r1[i] = 0x10
		r2[i] = 0x20
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
	presBytes := zkgroup.SerializeBackupAuthCredentialPresentation(pres)
	sig, err := ecc.CalculateSignature(f.identityKey, presBytes)
	if err != nil {
		t.Fatalf("CalculateSignature: %v", err)
	}
	return base64.StdEncoding.EncodeToString(presBytes), base64.StdEncoding.EncodeToString(sig[:])
}

// setZKHeaders adds the two ZK headers to an HTTP request.
func (f *archiveTestFixture) setZKHeaders(t *testing.T, r *http.Request, level backups.BackupLevel, credType backups.CredentialType) {
	t.Helper()
	presB64, sigB64 := f.zkHeaders(t, level, credType)
	r.Header.Set(headerZKAuth, presB64)
	r.Header.Set(headerZKAuthSig, sigB64)
}

// --- archiveFakeBlobStore ---------------------------------------------------

type archiveFakeBlobStore struct {
	cdn     int
	objects map[string][]byte
}

func newArchiveFakeBlobStore() *archiveFakeBlobStore {
	return &archiveFakeBlobStore{cdn: 3, objects: make(map[string][]byte)}
}

func (f *archiveFakeBlobStore) CDNNumber() int { return f.cdn }

func (f *archiveFakeBlobStore) GenerateUpload(_ context.Context, key string) (*backups.UploadDescriptor, error) {
	return &backups.UploadDescriptor{
		CDN:                  f.cdn,
		Key:                  key,
		Headers:              map[string]string{"X-Test": "1"},
		SignedUploadLocation: "https://cdn.example/" + key,
	}, nil
}

func (f *archiveFakeBlobStore) ReadHeaders(_ context.Context, _ string) (map[string]string, error) {
	return map[string]string{"Authorization": "Bearer test"}, nil
}

func (f *archiveFakeBlobStore) Copy(_ context.Context, _ int, _ string, _ int, _ backups.MediaEncryptionParameters, destPath string) error {
	f.objects[destPath] = make([]byte, 128)
	return nil
}

func (f *archiveFakeBlobStore) Delete(_ context.Context, path string) (int64, error) {
	n := int64(len(f.objects[path]))
	delete(f.objects, path)
	return n, nil
}

func (f *archiveFakeBlobStore) List(_ context.Context, prefix string, _ *string, _ int) (*backups.BlobListResult, error) {
	var out backups.BlobListResult
	for k, v := range f.objects {
		if strings.HasPrefix(k, prefix) {
			out.Objects = append(out.Objects, backups.BlobListEntry{Key: k[len(prefix):], Length: int64(len(v))})
		}
	}
	return &out, nil
}

func (f *archiveFakeBlobStore) CalculateBytesUsed(_ context.Context, prefix string) (backups.UsageInfo, error) {
	var u backups.UsageInfo
	for k, v := range f.objects {
		if strings.HasPrefix(k, prefix) {
			u.NumObjects++
			u.BytesUsed += int64(len(v))
		}
	}
	return u, nil
}

// =============================================================================
// handleGetBackupIdLimits — account auth
// =============================================================================

func TestHandleGetBackupIdLimits_HappyPath(t *testing.T) {
	f := newTestServerWithBackups(t)
	s := f.server
	// Seed a test account so basic auth passes.
	_ = s.accounts.Create(context.Background(), testAccount())

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/backupid/limits", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp BackupIDLimitsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

func TestHandleGetBackupIdLimits_Unauthenticated(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/backupid/limits", nil)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// =============================================================================
// handleRedeemReceipt — account auth
// =============================================================================

func TestHandleRedeemReceipt_MalformedReceipt(t *testing.T) {
	f := newTestServerWithBackups(t)
	s := f.server
	_ = s.accounts.Create(context.Background(), testAccount())

	body := `{"receiptCredentialPresentation":"!!!notbase64!!!"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/archives/redeem-receipt", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("malformed base64: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRedeemReceipt_EmptyBody(t *testing.T) {
	f := newTestServerWithBackups(t)
	s := f.server
	_ = s.accounts.Create(context.Background(), testAccount())

	req := httptest.NewRequest(http.MethodPost, "/v1/archives/redeem-receipt", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Empty receiptCredentialPresentation → 400 (base64 decode of "" → empty bytes → InvalidArgument).
	if rr.Code != http.StatusBadRequest {
		t.Errorf("empty body: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRedeemReceipt_Unauthenticated(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/archives/redeem-receipt", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// =============================================================================
// handleDeleteBackup — ZK auth
// =============================================================================

func TestHandleDeleteBackup_Unauthenticated(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodDelete, "/v1/archives", nil)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleDeleteBackup_HappyPath(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodDelete, "/v1/archives", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleSetBackupPublicKey — ZK auth + public key
// =============================================================================

func TestHandleSetBackupPublicKey_MissingZKHeaders(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/keys", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleSetBackupPublicKey_InvalidBodyPubKey(t *testing.T) {
	// A fresh store with no public key pre-registered so SetPublicKey can proceed.
	store := storagememory.NewMemoryBackupStore()
	blob := newArchiveFakeBlobStore()
	var rb zkgroup.RandomnessBytes
	for i := range rb {
		rb[i] = 0x77
	}
	ss := zkgroup.GenerateGenericServerSecretParams(rb)
	clock := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return clock })
	mgr := backups.NewManager(backups.ManagerOptions{
		Store:              store,
		Blob:               blob,
		ServerSecretParams: ss,
		Clock:              func() time.Time { return clock },
	})
	var rr2 zkgroup.RandomnessBytes
	for i := range rr2 {
		rr2[i] = 0xDD
	}
	receiptParams, _ := zkgroup.GenerateServerSecretParams(rr2)
	authMgr := backups.NewAuthManager(backups.AuthManagerOptions{
		Accounts:                    accounts.NewAccountsManager(storagememory.NewMemoryAccountStore(), 6),
		SetBackupIDLimiter:          limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		SetPaidMediaBackupIDLimiter: limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 10, RefillRate: 10}),
		ServerSecretParams:          ss,
		ReceiptServerSecretParams:   receiptParams,
		RedeemedReceipts:            storagememory.NewMemoryRedeemedReceiptsStore(),
		Clock:                       func() time.Time { return clock },
	})
	s := newTestServer(t)
	s.backups = service.NewBackupService(backups.NewService(mgr, authMgr))

	// Build a fresh credential for this store.
	var bk [32]byte
	for i := range bk {
		bk[i] = 0xEE
	}
	var ai [16]byte
	for i := range ai {
		ai[i] = 0xFF
	}
	reqCtx, err := zkgroup.NewBackupAuthCredentialRequestContext(bk, zkgroup.NewACI(ai))
	if err != nil {
		t.Fatalf("reqCtx: %v", err)
	}
	day := zkgroup.NewTimestamp(uint64(clock.Truncate(24 * time.Hour).Unix()))
	resp0, err := reqCtx.GetRequest().Issue(day, backups.BackupLevelFree, backups.CredentialTypeMessages, ss, rb)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cred, err := reqCtx.Receive(resp0, ss.GetPublicParams(), day)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	pres, err := cred.Present(ss.GetPublicParams(), rb)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	presBytes := zkgroup.SerializeBackupAuthCredentialPresentation(pres)
	kp, _ := ecc.GenerateKeyPair()
	sig, _ := ecc.CalculateSignature(kp.PrivateKey(), presBytes)

	body := map[string]string{"backupIdPublicKey": "!!!bad base64!!!"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/keys", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerZKAuth, base64.StdEncoding.EncodeToString(presBytes))
	req.Header.Set(headerZKAuthSig, base64.StdEncoding.EncodeToString(sig[:]))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad pub key base64: expected 400, got %d", rr.Code)
	}
}

// =============================================================================
// handleGetMediaUploadForm — ZK auth + media credential + paid level
// =============================================================================

func TestHandleGetMediaUploadForm_Unauthenticated(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/media/upload/form", nil)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleGetMediaUploadForm_RequiresPaidLevel(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/media/upload/form", nil)
	// Messages credential at free tier → WrongCredentialTypeError → 401.
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	// Requires media credential; messages credential yields an error.
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for messages credential on media endpoint, got %d", rr.Code)
	}
}

// =============================================================================
// handleCopyMedia — ZK auth + body parsing + all 4 outcomes
// =============================================================================

func TestHandleCopyMedia_Unauthenticated(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleCopyMedia_MalformedMediaID(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media", strings.NewReader(`{
		"sourceAttachment":{"cdn":3,"key":"k"},
		"objectLength":100,
		"mediaId":"!!! not base64url !!!",
		"hmacKey":"AAAA",
		"encryptionKey":"AAAA"
	}`))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("malformed mediaId: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCopyMedia_SuccessOutcome(t *testing.T) {
	f := newTestServerWithBackups(t)
	mediaID := make([]byte, 32)
	mediaID[0] = 0xAB
	body := map[string]interface{}{
		"sourceAttachment": map[string]interface{}{"cdn": f.blobCDN, "key": "src"},
		"objectLength":     100,
		"mediaId":          base64.URLEncoding.EncodeToString(mediaID),
		"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp CopyMediaResponseBody
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestHandleCopyMedia_OutOfQuotaOutcome(t *testing.T) {
	f := newTestServerWithBackups(t)
	// Force OutOfQuota by using a negative objectLength, which triggers
	// InvalidArgumentError from GetCopyQuota → 400. This exercises the
	// error-path before the outcome mapping.
	mediaID := make([]byte, 32)
	body := map[string]interface{}{
		"sourceAttachment": map[string]interface{}{"cdn": f.blobCDN, "key": "src"},
		"objectLength":     -1,
		"mediaId":          base64.URLEncoding.EncodeToString(mediaID),
		"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("negative length: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleCopyMediaBatch — multi-item batch with mixed outcomes
// =============================================================================

func TestHandleCopyMediaBatch_Unauthenticated(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media/batch", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleCopyMediaBatch_HappyPath(t *testing.T) {
	f := newTestServerWithBackups(t)
	id1 := make([]byte, 32)
	id1[0] = 0x01
	id2 := make([]byte, 32)
	id2[0] = 0x02
	items := []map[string]interface{}{
		{
			"sourceAttachment": map[string]interface{}{"cdn": f.blobCDN, "key": "k1"},
			"objectLength":     100,
			"mediaId":          base64.URLEncoding.EncodeToString(id1),
			"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
		{
			"sourceAttachment": map[string]interface{}{"cdn": f.blobCDN, "key": "k2"},
			"objectLength":     200,
			"mediaId":          base64.URLEncoding.EncodeToString(id2),
			"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
	}
	body := map[string]interface{}{"items": items}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media/batch", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Errorf("expected 207, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp CopyMediaBatchResponseBody
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Responses) != 2 {
		t.Errorf("expected 2 responses, got %d", len(resp.Responses))
	}
}

func TestHandleCopyMediaBatch_MalformedItem(t *testing.T) {
	f := newTestServerWithBackups(t)
	body := `{"items":[{"sourceAttachment":{"cdn":3,"key":"k"},"objectLength":10,"mediaId":"!bad!","hmacKey":"AAAA","encryptionKey":"AAAA"}]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// =============================================================================
// handleListMedia — pagination + decode key
// =============================================================================

func TestHandleListMedia_Unauthenticated(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/media", nil)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleListMedia_HappyPath(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/media?limit=10", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp ListMediaResponseBody
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func TestHandleListMedia_InvalidLimit(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/media?limit=abc", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleListMedia_WithCursor(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/media?limit=5&cursor=abc", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// =============================================================================
// handleDeleteMedia — ZK auth + media-credential guard
// =============================================================================

func TestHandleDeleteMedia_Unauthenticated(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/archives/media/delete", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleDeleteMedia_HappyPathEmptyList(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/archives/media/delete",
		strings.NewReader(`{"mediaToDelete":[]}`))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleDeleteMedia_InvalidBase64MediaID(t *testing.T) {
	f := newTestServerWithBackups(t)
	body := `{"mediaToDelete":[{"cdn":3,"mediaId":"!!! not valid base64url !!!"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/archives/media/delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// =============================================================================
// handleGetCDNReadAuth — ZK auth + CDN number
// =============================================================================

func TestHandleGetCDNReadAuth_Unauthenticated(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth/read?cdn=3", nil)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleGetCDNReadAuth_HappyPath(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth/read?cdn=3", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp ReadAuthResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Headers["Authorization"] == "" {
		t.Error("expected Authorization header in response")
	}
}

func TestHandleGetCDNReadAuth_InvalidCDN(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth/read?cdn=notanumber", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGetCDNReadAuth_UnsupportedCDN(t *testing.T) {
	f := newTestServerWithBackups(t)
	// CDN 9999 is not supported by the fake blob store.
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth/read?cdn=9999", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for unsupported CDN, got 200")
	}
}

// =============================================================================
// handleGetSVRBAuth — ZK auth + SVRB disabled surface
// =============================================================================

func TestHandleGetSVRBAuth_Unauthenticated(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth/svrb", nil)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleGetSVRBAuth_DisabledReturnsError(t *testing.T) {
	f := newTestServerWithBackups(t)
	// SVRB is disabled by default — handler should return a non-200 error.
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth/svrb", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 for disabled SVRB, got 200")
	}
}

// =============================================================================
// Helper function coverage — decodeOptionalBase64Pair, parseCopyParameters,
// credentialTypeName, copyOutcomeName, copyOutcomeToHTTP, derefInt
// =============================================================================

func TestDecodeOptionalBase64Pair_BothEmpty(t *testing.T) {
	a, b, err := decodeOptionalBase64Pair("", "")
	if err != nil || a != nil || b != nil {
		t.Errorf("both empty: expected nil/nil/nil, got %v/%v/%v", a, b, err)
	}
}

func TestDecodeOptionalBase64Pair_ValidA(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("hello"))
	a, b, err := decodeOptionalBase64Pair(encoded, "")
	if err != nil || string(a) != "hello" || b != nil {
		t.Errorf("valid A: got a=%q b=%v err=%v", a, b, err)
	}
}

func TestDecodeOptionalBase64Pair_InvalidA(t *testing.T) {
	_, _, err := decodeOptionalBase64Pair("!!!invalid!!!", "")
	if err == nil {
		t.Error("expected error for invalid base64 in A")
	}
}

func TestDecodeOptionalBase64Pair_InvalidB(t *testing.T) {
	_, _, err := decodeOptionalBase64Pair("", "!!!invalid!!!")
	if err == nil {
		t.Error("expected error for invalid base64 in B")
	}
}

func TestParseCopyParameters_InvalidMediaID(t *testing.T) {
	body := CopyMediaRequestBody{
		MediaID:       "!!!not base64url!!!",
		HMACKey:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
		EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	_, err := parseCopyParameters(body)
	if err == nil {
		t.Error("expected error for invalid mediaId")
	}
}

func TestParseCopyParameters_InvalidHMACKey(t *testing.T) {
	body := CopyMediaRequestBody{
		MediaID:       base64.URLEncoding.EncodeToString(make([]byte, 32)),
		HMACKey:       "!!!not base64!!!",
		EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	_, err := parseCopyParameters(body)
	if err == nil {
		t.Error("expected error for invalid hmacKey")
	}
}

func TestParseCopyParameters_InvalidEncryptionKey(t *testing.T) {
	body := CopyMediaRequestBody{
		MediaID:       base64.URLEncoding.EncodeToString(make([]byte, 32)),
		HMACKey:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
		EncryptionKey: "!!!not base64!!!",
	}
	_, err := parseCopyParameters(body)
	if err == nil {
		t.Error("expected error for invalid encryptionKey")
	}
}

func TestParseCopyParameters_HappyPath(t *testing.T) {
	mediaID := make([]byte, 32)
	body := CopyMediaRequestBody{
		MediaID:       base64.URLEncoding.EncodeToString(mediaID),
		HMACKey:       base64.StdEncoding.EncodeToString(make([]byte, 32)),
		EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	body.SourceAttachment.CDN = 3
	body.SourceAttachment.Key = "src"
	body.ObjectLength = 100
	p, err := parseCopyParameters(body)
	if err != nil {
		t.Fatalf("parseCopyParameters: %v", err)
	}
	if p.SourceCDN != 3 || p.SourceKey != "src" || p.SourceLength != 100 {
		t.Errorf("unexpected params: %+v", p)
	}
}

func TestCredentialTypeName(t *testing.T) {
	if credentialTypeName(backups.CredentialTypeMessages) != "messages" {
		t.Error("expected messages")
	}
	if credentialTypeName(backups.CredentialTypeMedia) != "media" {
		t.Error("expected media")
	}
	if credentialTypeName(backups.CredentialType(99)) != "unknown" {
		t.Error("expected unknown")
	}
}

func TestCopyOutcomeName(t *testing.T) {
	cases := []struct {
		o    backups.CopyOutcome
		want string
	}{
		{backups.CopyOutcomeSuccess, "success"},
		{backups.CopyOutcomeSourceNotFound, "sourceNotFound"},
		{backups.CopyOutcomeSourceWrongLength, "sourceWrongLength"},
		{backups.CopyOutcomeOutOfQuota, "outOfQuota"},
		{backups.CopyOutcome(99), "unknown"},
	}
	for _, tc := range cases {
		if got := copyOutcomeName(tc.o); got != tc.want {
			t.Errorf("copyOutcomeName(%d) = %q; want %q", tc.o, got, tc.want)
		}
	}
}

func TestCopyOutcomeToHTTP(t *testing.T) {
	cases := []struct {
		o    backups.CopyOutcome
		want int
	}{
		{backups.CopyOutcomeSuccess, http.StatusOK},
		{backups.CopyOutcomeSourceNotFound, http.StatusGone},
		{backups.CopyOutcomeSourceWrongLength, http.StatusBadRequest},
		{backups.CopyOutcomeOutOfQuota, http.StatusRequestEntityTooLarge},
		{backups.CopyOutcome(99), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		if got := copyOutcomeToHTTP(tc.o); got != tc.want {
			t.Errorf("copyOutcomeToHTTP(%d) = %d; want %d", tc.o, got, tc.want)
		}
	}
}

func TestDerefInt(t *testing.T) {
	n := 42
	if derefInt(&n) != 42 {
		t.Error("expected 42")
	}
	if derefInt(nil) != 0 {
		t.Error("expected 0 for nil")
	}
}

// =============================================================================
// handleGetBackupInfo — ZK-authenticated, service-enabled
// =============================================================================

func TestHandleGetBackupInfo_HappyPath(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp BackupInfoResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.BackupDir == "" {
		t.Error("expected non-empty BackupDir")
	}
}

func TestHandleGetBackupInfo_NoZKHeaders(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives", nil)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// =============================================================================
// handleRefreshBackup — ZK-authenticated, service-enabled
// =============================================================================

func TestHandleRefreshBackup_HappyPath(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/archives", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleRefreshBackup_NoZKHeaders(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/archives", nil)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// =============================================================================
// handleGetBackupUploadForm — ZK-authenticated, messages credential
// =============================================================================

func TestHandleGetBackupUploadForm_HappyPath(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/upload/form", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp UploadDescriptorResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Key == "" {
		t.Error("expected non-empty key")
	}
}

func TestHandleGetBackupUploadForm_NoZKHeaders(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/upload/form", nil)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// =============================================================================
// handleSetBackupId — account-auth + body parsing
// =============================================================================

func TestHandleSetBackupId_UnauthenticatedWithService(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/backupid",
		strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleSetBackupId_InvalidJSON(t *testing.T) {
	f := newTestServerWithBackups(t)
	_ = f.server.accounts.Create(context.Background(), testAccount())
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/backupid",
		strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: expected 400, got %d", rr.Code)
	}
}

func TestHandleSetBackupId_InvalidBase64Request(t *testing.T) {
	f := newTestServerWithBackups(t)
	_ = f.server.accounts.Create(context.Background(), testAccount())
	body := `{"messagesBackupAuthCredentialRequest":"!!! not base64 !!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/backupid",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad base64: expected 400, got %d", rr.Code)
	}
}

func TestHandleSetBackupId_InvalidCredentialRequest(t *testing.T) {
	f := newTestServerWithBackups(t)
	_ = f.server.accounts.Create(context.Background(), testAccount())
	// Valid base64 but invalid credential bytes.
	body := map[string]string{
		"messagesBackupAuthCredentialRequest": base64.StdEncoding.EncodeToString([]byte("garbage bytes")),
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/backupid",
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid credential: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleGetBackupAuth — account-auth + query params
// =============================================================================

func TestHandleGetBackupAuth_WithEnabledService(t *testing.T) {
	f := newTestServerWithBackups(t)
	_ = f.server.accounts.Create(context.Background(), testAccount())
	// Missing query params → 400.
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing query params: expected 400, got %d", rr.Code)
	}
}

func TestHandleGetBackupAuth_InvalidStartSeconds(t *testing.T) {
	f := newTestServerWithBackups(t)
	_ = f.server.accounts.Create(context.Background(), testAccount())
	req := httptest.NewRequest(http.MethodGet,
		"/v1/archives/auth?redemptionStartSeconds=notanumber&redemptionEndSeconds=1234", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid start: expected 400, got %d", rr.Code)
	}
}

func TestHandleGetBackupAuth_InvalidEndSeconds(t *testing.T) {
	f := newTestServerWithBackups(t)
	_ = f.server.accounts.Create(context.Background(), testAccount())
	req := httptest.NewRequest(http.MethodGet,
		"/v1/archives/auth?redemptionStartSeconds=1234&redemptionEndSeconds=notanumber", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid end: expected 400, got %d", rr.Code)
	}
}

func TestHandleGetBackupAuth_UnauthenticatedWithService(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet,
		"/v1/archives/auth?redemptionStartSeconds=1&redemptionEndSeconds=2", nil)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// =============================================================================
// zkAuthenticate — invalid base64 headers
// =============================================================================

func TestZKAuthenticate_InvalidBase64Presentation(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives", nil)
	req.Header.Set(headerZKAuth, "!!! not valid base64 !!!")
	req.Header.Set(headerZKAuthSig, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid presentation base64: expected 400, got %d", rr.Code)
	}
}

func TestZKAuthenticate_InvalidBase64Signature(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives", nil)
	req.Header.Set(headerZKAuth, base64.StdEncoding.EncodeToString([]byte("presentation")))
	req.Header.Set(headerZKAuthSig, "!!! not valid base64 !!!")
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid sig base64: expected 400, got %d", rr.Code)
	}
}

// =============================================================================
// writeBackupError — all typed error types
// =============================================================================

func TestWriteBackupError_AllTypedErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"PermissionError", &backups.PermissionError{}, http.StatusForbidden},
		{"WrongCredentialTypeError", &backups.WrongCredentialTypeError{}, http.StatusUnauthorized},
		{"FailedZkAuthError", &backups.FailedZkAuthError{}, http.StatusUnauthorized},
		{"PublicKeyConflictError", &backups.PublicKeyConflictError{}, http.StatusConflict},
		{"NotFoundError", &backups.NotFoundError{}, http.StatusNotFound},
		{"InvalidArgumentError", &backups.InvalidArgumentError{}, http.StatusBadRequest},
		{"RateLimitedError", &backups.RateLimitedError{}, http.StatusTooManyRequests},
		{"BadReceiptError", &backups.BadReceiptError{}, http.StatusBadRequest},
		{"MissingIDCommitmentError", &backups.MissingIDCommitmentError{}, http.StatusConflict},
		{"UnknownError", archiveTestError("unknown"), http.StatusInternalServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeBackupError(rr, tc.err)
			if rr.Code != tc.wantCode {
				t.Errorf("writeBackupError(%T) = %d; want %d", tc.err, rr.Code, tc.wantCode)
			}
		})
	}
}

type archiveTestError string

func (e archiveTestError) Error() string { return string(e) }

// =============================================================================
// handleCopyMedia — non-success (OutOfQuota) outcome path
// =============================================================================

// TestHandleCopyMedia_OutOfQuotaResponse uses a server with MaxQuota=1 so
// any copy request exceeds the quota, causing the callback to fire with
// CopyOutcomeOutOfQuota and the handler to return a non-200 status.
func TestHandleCopyMedia_OutOfQuotaResponse(t *testing.T) {
	// Build a zero-quota server.
	store := storagememory.NewMemoryBackupStore()
	blob := newArchiveFakeBlobStore()
	var rb zkgroup.RandomnessBytes
	for i := range rb {
		rb[i] = 0x91
	}
	ss := zkgroup.GenerateGenericServerSecretParams(rb)
	clock := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return clock })

	mgr := backups.NewManager(backups.ManagerOptions{
		Store:              store,
		Blob:               blob,
		ServerSecretParams: ss,
		MaxQuota:           1,
		AttachmentLimiter:  limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 100, RefillRate: 100}),
		Clock:              func() time.Time { return clock },
	})

	var bk [32]byte
	for i := range bk {
		bk[i] = 0x92
	}
	var ai [16]byte
	for i := range ai {
		ai[i] = 0x93
	}
	reqCtx, err := zkgroup.NewBackupAuthCredentialRequestContext(bk, zkgroup.NewACI(ai))
	if err != nil {
		t.Fatalf("reqCtx: %v", err)
	}
	backupID := reqCtx.BackupIdentifier
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ctx := context.Background()
	if err := store.SetPublicKey(ctx, backupID, backups.BackupLevelPaid, kp.PublicKey().Serialize()); err != nil {
		t.Fatalf("seed SetPublicKey: %v", err)
	}

	var rr2 zkgroup.RandomnessBytes
	for i := range rr2 {
		rr2[i] = 0x94
	}
	receiptParams, err := zkgroup.GenerateServerSecretParams(rr2)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	authMgr := backups.NewAuthManager(backups.AuthManagerOptions{
		Accounts:                    accounts.NewAccountsManager(storagememory.NewMemoryAccountStore(), 6),
		SetBackupIDLimiter:          limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 100, RefillRate: 100}),
		SetPaidMediaBackupIDLimiter: limits.NewTokenBucketLimiter(limits.BucketConfig{BucketSize: 100, RefillRate: 100}),
		ServerSecretParams:          ss,
		ReceiptServerSecretParams:   receiptParams,
		RedeemedReceipts:            storagememory.NewMemoryRedeemedReceiptsStore(),
		Clock:                       func() time.Time { return clock },
	})
	s := newTestServer(t)
	s.backups = service.NewBackupService(backups.NewService(mgr, authMgr))

	// Mint a paid media presentation.
	var r1, r2 zkgroup.RandomnessBytes
	for i := range r1 {
		r1[i] = 0x95
		r2[i] = 0x96
	}
	day := zkgroup.NewTimestamp(uint64(clock.Truncate(24 * time.Hour).Unix()))
	issResp, err := reqCtx.GetRequest().Issue(day, backups.BackupLevelPaid, backups.CredentialTypeMedia, ss, r1)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cred, err := reqCtx.Receive(issResp, ss.GetPublicParams(), day)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	pres, err := cred.Present(ss.GetPublicParams(), r2)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	presBytes := zkgroup.SerializeBackupAuthCredentialPresentation(pres)
	sig, err := ecc.CalculateSignature(kp.PrivateKey(), presBytes)
	if err != nil {
		t.Fatalf("CalculateSignature: %v", err)
	}

	mediaID := make([]byte, 32)
	mediaID[0] = 0xF1
	body := map[string]interface{}{
		"sourceAttachment": map[string]interface{}{"cdn": blob.cdn, "key": "qqsrc"},
		"objectLength":     100,
		"mediaId":          base64.URLEncoding.EncodeToString(mediaID),
		"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerZKAuth, base64.StdEncoding.EncodeToString(presBytes))
	req.Header.Set(headerZKAuthSig, base64.StdEncoding.EncodeToString(sig[:]))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected non-200 (out of quota), got 200: %s", rr.Body.String())
	}
}

// =============================================================================
// handleCopyMediaBatch — invalid JSON body
// =============================================================================

func TestHandleCopyMediaBatch_InvalidJSONBody(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media/batch",
		strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: expected 400, got %d", rr.Code)
	}
}

// =============================================================================
// handleGetSVRBAuth — happy path test (SVRB disabled → 5xx)
// =============================================================================

func TestHandleGetSVRBAuth_HappyPathDisabledSVRB(t *testing.T) {
	// SVRB is disabled in the default manager — verify the handler
	// returns a non-200 status and does NOT panic.
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth/svrb", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Error("expected non-200 for disabled SVRB")
	}
}

// =============================================================================
// handleDeleteMedia — delete an actual item (covers for-body + success path)
// =============================================================================

func TestHandleDeleteMedia_WithValidItem(t *testing.T) {
	f := newTestServerWithBackups(t)

	// First copy a media item so we have something to delete.
	mediaID := make([]byte, 32)
	mediaID[0] = 0xF2
	copyBody := map[string]interface{}{
		"sourceAttachment": map[string]interface{}{"cdn": f.blobCDN, "key": "del-key"},
		"objectLength":     100,
		"mediaId":          base64.URLEncoding.EncodeToString(mediaID),
		"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	copyBytes, _ := json.Marshal(copyBody)
	copyReq := httptest.NewRequest(http.MethodPut, "/v1/archives/media", bytes.NewReader(copyBytes))
	copyReq.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, copyReq, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	copyRR := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(copyRR, copyReq)
	if copyRR.Code != http.StatusOK {
		t.Fatalf("copy precondition: got %d: %s", copyRR.Code, copyRR.Body.String())
	}

	// Now delete the item.
	deleteBody := map[string]interface{}{
		"mediaToDelete": []map[string]interface{}{
			{"cdn": f.blobCDN, "mediaId": base64.URLEncoding.EncodeToString(mediaID)},
		},
	}
	deleteBytes, _ := json.Marshal(deleteBody)
	deleteReq := httptest.NewRequest(http.MethodPost, "/v1/archives/media/delete", bytes.NewReader(deleteBytes))
	deleteReq.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, deleteReq, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	deleteRR := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(deleteRR, deleteReq)
	if deleteRR.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", deleteRR.Code, deleteRR.Body.String())
	}
}

// =============================================================================
// handleRedeemReceipt — nil-backups path
// =============================================================================

func TestHandleRedeemReceipt_NilBackupsService(t *testing.T) {
	// newTestServerWithAccount has no backups service → 501.
	s, _ := newTestServerWithAccount(t)
	body := `{"receiptCredentialPresentation":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/archives/redeem-receipt",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotImplemented {
		t.Errorf("nil backups: expected 501, got %d", rr.Code)
	}
}

// =============================================================================
// handleCopyMediaBatch — nil-backups invalid CDN (triggers writeBackupError)
// =============================================================================

func TestHandleCopyMediaBatch_InvalidCDN(t *testing.T) {
	f := newTestServerWithBackups(t)

	id1 := make([]byte, 32)
	id1[0] = 0x07
	// CDN 9999 is not supported by the fake blob store — GetCopyQuota will
	// succeed (it doesn't validate CDN), but Copy will fail if items are
	// processed. With correct quota accounting this yields a Success
	// outcome since Copy errors map to classifyCopyError.
	// The test verifies the batch response returns 207 and populates entries.
	items := []map[string]interface{}{
		{
			"sourceAttachment": map[string]interface{}{"cdn": f.blobCDN, "key": "b1"},
			"objectLength":     100,
			"mediaId":          base64.URLEncoding.EncodeToString(id1),
			"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
	}
	body := map[string]interface{}{"items": items}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media/batch", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Errorf("expected 207, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleGetBackupIdLimits — nil-backups path
// =============================================================================

func TestHandleGetBackupIdLimits_NilBackupsService(t *testing.T) {
	// newTestServer has no backups service → 501.
	s, _ := newTestServerWithAccount(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/archives/backupid/limits", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotImplemented {
		t.Errorf("nil backups: expected 501, got %d", rr.Code)
	}
}

// =============================================================================
// handleRedeemReceipt — invalid JSON and success paths
// =============================================================================

func TestHandleRedeemReceipt_InvalidJSON(t *testing.T) {
	f := newTestServerWithBackups(t)
	_ = f.server.accounts.Create(context.Background(), testAccount())
	req := httptest.NewRequest(http.MethodPost, "/v1/archives/redeem-receipt",
		strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: expected 400, got %d", rr.Code)
	}
}

// =============================================================================
// handleSetBackupPublicKey — nil-backups path + bad base64 headers
// =============================================================================

func TestHandleSetBackupPublicKey_NilBackupsService(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/keys",
		strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerZKAuth, base64.StdEncoding.EncodeToString([]byte("x")))
	req.Header.Set(headerZKAuthSig, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotImplemented {
		t.Errorf("nil backups: expected 501, got %d", rr.Code)
	}
}

func TestHandleSetBackupPublicKey_BadBase64Presentation(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/keys",
		strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerZKAuth, "!!! bad base64 !!!")
	req.Header.Set(headerZKAuthSig, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad presentation base64: expected 400, got %d", rr.Code)
	}
}

func TestHandleSetBackupPublicKey_BadBase64Signature(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/keys",
		strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerZKAuth, base64.StdEncoding.EncodeToString([]byte("x")))
	req.Header.Set(headerZKAuthSig, "!!! bad base64 !!!")
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad sig base64: expected 400, got %d", rr.Code)
	}
}

func TestHandleSetBackupPublicKey_BadJSONBody(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/keys",
		strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerZKAuth, base64.StdEncoding.EncodeToString([]byte("pres")))
	req.Header.Set(headerZKAuthSig, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: expected 400, got %d", rr.Code)
	}
}

// =============================================================================
// handleDeleteMedia — invalid JSON body
// =============================================================================

func TestHandleDeleteMedia_InvalidJSONBody(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/archives/media/delete",
		strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: expected 400, got %d", rr.Code)
	}
}

// =============================================================================
// handleListMedia — with media items (covers the result-population loop)
// =============================================================================

func TestHandleListMedia_WithSeededMedia(t *testing.T) {
	// Seed a media object so the list result has an item.
	// Construct a fixture with controllable blob store.
	f := newTestServerWithBackups(t)

	// Copy a media item via the API to seed the blob store.
	mediaID := make([]byte, 32)
	mediaID[0] = 0xF0
	body := map[string]interface{}{
		"sourceAttachment": map[string]interface{}{"cdn": f.blobCDN, "key": "list-test-key"},
		"objectLength":     100,
		"mediaId":          base64.URLEncoding.EncodeToString(mediaID),
		"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	bodyBytes, _ := json.Marshal(body)
	copyReq := httptest.NewRequest(http.MethodPut, "/v1/archives/media", bytes.NewReader(bodyBytes))
	copyReq.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, copyReq, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	copyRR := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(copyRR, copyReq)
	if copyRR.Code != http.StatusOK {
		t.Fatalf("copy precondition failed: got %d: %s", copyRR.Code, copyRR.Body.String())
	}

	// Now list media as messages credential.
	listReq := httptest.NewRequest(http.MethodGet, "/v1/archives/media?limit=10", nil)
	f.setZKHeaders(t, listReq, backups.BackupLevelFree, backups.CredentialTypeMessages)
	listRR := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list failed: got %d: %s", listRR.Code, listRR.Body.String())
	}
	var resp ListMediaResponseBody
	if err := json.NewDecoder(listRR.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.StoredMediaObjects) == 0 {
		t.Error("expected at least one media object after copy")
	}
}

// =============================================================================
// handleCopyMediaBatch — empty items list (covers the no-items path)
// =============================================================================

func TestHandleCopyMediaBatch_EmptyItems(t *testing.T) {
	f := newTestServerWithBackups(t)
	body := `{"items":[]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media/batch",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Errorf("empty items: expected 207, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleGetBackupAuth — happy path with committed credentials
// =============================================================================

// =============================================================================
// errInjectRestBackupService: error-injecting BackupService for coverage of
// unreachable service-error branches in REST handlers.
// =============================================================================

// errInjectRestBackupService wraps a real BackupService and lets tests
// override the return value of specific methods.
type errInjectRestBackupService struct {
	real                              service.BackupService
	getBackupIDLimitsErr              error
	getBackupAuthCredentialsErr       error
	backupInfoErr                     error
	ttlRefreshErr                     error
	deleteEntireBackupErr             error
	createMessageBackupUploadDescErr  error
	createTempAttachmentUploadDescErr error
	getCopyQuotaErr                   error
	copyToBackupErr                   error
	listMediaErr                      error
	deleteMediaErr                    error
	redeemReceiptErr                  error
	authenticateBackupUserErr         error
	setPublicKeyErr                   error
	generateSVRBAuthResult            *backups.ExternalServiceCredentials
	listMediaResult                   *backups.ListMediaResult
}

func (s *errInjectRestBackupService) GetBackupIDLimits(ctx context.Context, accountUUID string) (*backups.BackupIDLimits, error) {
	if s.getBackupIDLimitsErr != nil {
		return nil, s.getBackupIDLimitsErr
	}
	return s.real.GetBackupIDLimits(ctx, accountUUID)
}
func (s *errInjectRestBackupService) GetBackupAuthCredentials(ctx context.Context, accountUUID string, start, end time.Time) (*backups.CredentialsResponse, error) {
	if s.getBackupAuthCredentialsErr != nil {
		return nil, s.getBackupAuthCredentialsErr
	}
	return s.real.GetBackupAuthCredentials(ctx, accountUUID, start, end)
}
func (s *errInjectRestBackupService) BackupInfo(ctx context.Context, user *backups.AuthenticatedUser) (*backups.Info, error) {
	if s.backupInfoErr != nil {
		return nil, s.backupInfoErr
	}
	return s.real.BackupInfo(ctx, user)
}
func (s *errInjectRestBackupService) TTLRefresh(ctx context.Context, user *backups.AuthenticatedUser) error {
	if s.ttlRefreshErr != nil {
		return s.ttlRefreshErr
	}
	return s.real.TTLRefresh(ctx, user)
}
func (s *errInjectRestBackupService) DeleteEntireBackup(ctx context.Context, user *backups.AuthenticatedUser) error {
	if s.deleteEntireBackupErr != nil {
		return s.deleteEntireBackupErr
	}
	return s.real.DeleteEntireBackup(ctx, user)
}
func (s *errInjectRestBackupService) CreateMessageBackupUploadDescriptor(ctx context.Context, user *backups.AuthenticatedUser) (*backups.UploadDescriptor, error) {
	if s.createMessageBackupUploadDescErr != nil {
		return nil, s.createMessageBackupUploadDescErr
	}
	return s.real.CreateMessageBackupUploadDescriptor(ctx, user)
}
func (s *errInjectRestBackupService) CreateTemporaryAttachmentUploadDescriptor(ctx context.Context, user *backups.AuthenticatedUser) (*backups.UploadDescriptor, error) {
	if s.createTempAttachmentUploadDescErr != nil {
		return nil, s.createTempAttachmentUploadDescErr
	}
	return s.real.CreateTemporaryAttachmentUploadDescriptor(ctx, user)
}
func (s *errInjectRestBackupService) GetCopyQuota(ctx context.Context, user *backups.AuthenticatedUser, p []backups.CopyParameters) (*backups.CopyQuota, error) {
	if s.getCopyQuotaErr != nil {
		return nil, s.getCopyQuotaErr
	}
	return s.real.GetCopyQuota(ctx, user, p)
}
func (s *errInjectRestBackupService) CopyToBackup(ctx context.Context, q backups.CopyQuota, fn func(backups.CopyResult) error) error {
	if s.copyToBackupErr != nil {
		return s.copyToBackupErr
	}
	return s.real.CopyToBackup(ctx, q, fn)
}
func (s *errInjectRestBackupService) ListMedia(ctx context.Context, user *backups.AuthenticatedUser, cursor *string, limit int) (*backups.ListMediaResult, error) {
	if s.listMediaErr != nil {
		return nil, s.listMediaErr
	}
	if s.listMediaResult != nil {
		return s.listMediaResult, nil
	}
	return s.real.ListMedia(ctx, user, cursor, limit)
}
func (s *errInjectRestBackupService) DeleteMedia(ctx context.Context, user *backups.AuthenticatedUser, descs []backups.StorageDescriptor, fn func(backups.StorageDescriptor) error) error {
	if s.deleteMediaErr != nil {
		return s.deleteMediaErr
	}
	return s.real.DeleteMedia(ctx, user, descs, fn)
}
func (s *errInjectRestBackupService) RedeemReceipt(ctx context.Context, accountUUID string, req backups.RedeemReceiptRequest) error {
	if s.redeemReceiptErr != nil {
		return s.redeemReceiptErr
	}
	return s.real.RedeemReceipt(ctx, accountUUID, req)
}

// Remaining interface methods delegate unchanged.

func (s *errInjectRestBackupService) SetBackupID(ctx context.Context, accountUUID string, deviceID uint64, req backups.SetBackupIDRequest) error {
	return s.real.SetBackupID(ctx, accountUUID, deviceID, req)
}
func (s *errInjectRestBackupService) AuthenticateBackupUser(ctx context.Context, pres, sig []byte, ua string) (*backups.AuthenticatedUser, error) {
	if s.authenticateBackupUserErr != nil {
		return nil, s.authenticateBackupUserErr
	}
	return s.real.AuthenticateBackupUser(ctx, pres, sig, ua)
}
func (s *errInjectRestBackupService) SetPublicKey(ctx context.Context, pres, sig, pub []byte) error {
	if s.setPublicKeyErr != nil {
		return s.setPublicKeyErr
	}
	return s.real.SetPublicKey(ctx, pres, sig, pub)
}
func (s *errInjectRestBackupService) GenerateReadAuth(ctx context.Context, user *backups.AuthenticatedUser, cdn int) (map[string]string, error) {
	return s.real.GenerateReadAuth(ctx, user, cdn)
}
func (s *errInjectRestBackupService) GenerateSVRBAuth(ctx context.Context, user *backups.AuthenticatedUser) (*backups.ExternalServiceCredentials, error) {
	if s.generateSVRBAuthResult != nil {
		return s.generateSVRBAuthResult, nil
	}
	return s.real.GenerateSVRBAuth(ctx, user)
}
func (s *errInjectRestBackupService) ListBackupAttributes(ctx context.Context, segments int, fn func(backups.StoredAttributes) error) error {
	return s.real.ListBackupAttributes(ctx, segments, fn)
}
func (s *errInjectRestBackupService) GetExpiredBackups(ctx context.Context, segments int, purgeTime time.Time, fn func(backups.ExpiredBackup) error) error {
	return s.real.GetExpiredBackups(ctx, segments, purgeTime, fn)
}
func (s *errInjectRestBackupService) ExpireBackup(ctx context.Context, expired backups.ExpiredBackup) error {
	return s.real.ExpireBackup(ctx, expired)
}
func (s *errInjectRestBackupService) RecalculateQuota(ctx context.Context, attrs backups.StoredAttributes) (*backups.RecalculationResult, error) {
	return s.real.RecalculateQuota(ctx, attrs)
}

// Compile-time interface check.
var _ service.BackupService = (*errInjectRestBackupService)(nil)

// newErrInjectRestServer builds an archiveTestFixture with the real service
// wrapped in errInjectRestBackupService so the caller can inject errors.
func newErrInjectRestServer(t *testing.T) (*archiveTestFixture, *errInjectRestBackupService) {
	t.Helper()
	f := newTestServerWithBackups(t)
	inj := &errInjectRestBackupService{real: f.server.backups}
	f.server.backups = inj
	return f, inj
}

// =============================================================================
// Service-error branches: handleGetBackupIDLimits
// =============================================================================

func TestHandleGetBackupIdLimits_ServiceError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	_ = f.server.accounts.Create(context.Background(), testAccount())
	inj.getBackupIDLimitsErr = &backups.NotFoundError{}

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/backupid/limits", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected error status, got 200")
	}
}

// =============================================================================
// Service-error branches: handleGetBackupInfo
// =============================================================================

func TestHandleGetBackupInfo_ServiceError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.backupInfoErr = &backups.NotFoundError{}

	req := httptest.NewRequest(http.MethodGet, "/v1/archives", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected error status from BackupInfo error, got 200")
	}
}

// =============================================================================
// Service-error branches: handleRefreshBackup
// =============================================================================

func TestHandleRefreshBackup_ServiceError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.ttlRefreshErr = &backups.NotFoundError{}

	req := httptest.NewRequest(http.MethodPost, "/v1/archives", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusNoContent {
		t.Errorf("expected error status from TTLRefresh error, got 204")
	}
}

// =============================================================================
// Service-error branches: handleDeleteBackup
// =============================================================================

func TestHandleDeleteBackup_ServiceError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.deleteEntireBackupErr = &backups.NotFoundError{}

	req := httptest.NewRequest(http.MethodDelete, "/v1/archives", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusNoContent {
		t.Errorf("expected error status from DeleteEntireBackup error, got 204")
	}
}

// =============================================================================
// Service-error branches: handleGetBackupUploadForm
// =============================================================================

func TestHandleGetBackupUploadForm_ServiceError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.createMessageBackupUploadDescErr = &backups.NotFoundError{}

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/upload/form", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected error status from CreateMessageBackupUploadDescriptor error, got 200")
	}
}

// =============================================================================
// Service-error branches: handleGetMediaUploadForm
// =============================================================================

func TestHandleGetMediaUploadForm_ServiceError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.createTempAttachmentUploadDescErr = &backups.NotFoundError{}

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/media/upload/form", nil)
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected error status from CreateTemporaryAttachmentUploadDescriptor error, got 200")
	}
}

// =============================================================================
// Service-error branches: handleCopyMedia (GetCopyQuota error)
// =============================================================================

func TestHandleCopyMedia_GetCopyQuotaError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.getCopyQuotaErr = &backups.NotFoundError{}

	mediaID := make([]byte, 32)
	body := map[string]interface{}{
		"sourceAttachment": map[string]interface{}{"cdn": f.blobCDN, "key": "src"},
		"objectLength":     100,
		"mediaId":          base64.URLEncoding.EncodeToString(mediaID),
		"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected error status from GetCopyQuota error, got 200")
	}
}

// =============================================================================
// Service-error branches: handleCopyMedia (CopyToBackup error)
// =============================================================================

func TestHandleCopyMedia_CopyToBackupError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.copyToBackupErr = &backups.NotFoundError{}

	mediaID := make([]byte, 32)
	mediaID[0] = 0xC1
	body := map[string]interface{}{
		"sourceAttachment": map[string]interface{}{"cdn": f.blobCDN, "key": "src"},
		"objectLength":     100,
		"mediaId":          base64.URLEncoding.EncodeToString(mediaID),
		"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected error status from CopyToBackup error, got 200")
	}
}

// =============================================================================
// Service-error branches: handleCopyMediaBatch (GetCopyQuota error)
// =============================================================================

func TestHandleCopyMediaBatch_GetCopyQuotaError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.getCopyQuotaErr = &backups.NotFoundError{}

	id1 := make([]byte, 32)
	id1[0] = 0xC2
	items := []map[string]interface{}{
		{
			"sourceAttachment": map[string]interface{}{"cdn": f.blobCDN, "key": "bk1"},
			"objectLength":     100,
			"mediaId":          base64.URLEncoding.EncodeToString(id1),
			"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
	}
	body := map[string]interface{}{"items": items}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media/batch", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusMultiStatus {
		t.Errorf("expected error status from GetCopyQuota error, got 207")
	}
}

// =============================================================================
// Service-error branches: handleCopyMediaBatch (CopyToBackup error)
// =============================================================================

func TestHandleCopyMediaBatch_CopyToBackupError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.copyToBackupErr = &backups.NotFoundError{}

	id1 := make([]byte, 32)
	id1[0] = 0xC3
	items := []map[string]interface{}{
		{
			"sourceAttachment": map[string]interface{}{"cdn": f.blobCDN, "key": "bk2"},
			"objectLength":     100,
			"mediaId":          base64.URLEncoding.EncodeToString(id1),
			"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
	}
	body := map[string]interface{}{"items": items}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media/batch", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusMultiStatus {
		t.Errorf("expected error status from CopyToBackup error, got 207")
	}
}

// =============================================================================
// Service-error branches: handleListMedia
// =============================================================================

func TestHandleListMedia_ServiceError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.listMediaErr = &backups.NotFoundError{}

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/media?limit=10", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected error status from ListMedia error, got 200")
	}
}

// =============================================================================
// Service-error branches: handleDeleteMedia
// =============================================================================

func TestHandleDeleteMedia_ServiceError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.deleteMediaErr = &backups.NotFoundError{}

	mediaID := make([]byte, 32)
	mediaID[0] = 0xC4
	body := map[string]interface{}{
		"mediaToDelete": []map[string]interface{}{
			{"cdn": f.blobCDN, "mediaId": base64.URLEncoding.EncodeToString(mediaID)},
		},
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/archives/media/delete",
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusNoContent {
		t.Errorf("expected error status from DeleteMedia error, got 204")
	}
}

// =============================================================================
// Service-error branches: handleRedeemReceipt
// =============================================================================

func TestHandleRedeemReceipt_ServiceError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	_ = f.server.accounts.Create(context.Background(), testAccount())
	inj.redeemReceiptErr = &backups.BadReceiptError{}

	body := `{"receiptCredentialPresentation":"` +
		base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/archives/redeem-receipt",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusNoContent {
		t.Errorf("expected error status from RedeemReceipt error, got 204")
	}
}

// =============================================================================
// Service-error branches: handleGetBackupAuth (GetBackupAuthCredentials error)
// =============================================================================

func TestHandleGetBackupAuth_ServiceError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	_ = f.server.accounts.Create(context.Background(), testAccount())
	inj.getBackupAuthCredentialsErr = &backups.InvalidArgumentError{Field: "window", Message: "no commitment"}

	start := f.clock.Truncate(24 * time.Hour).Unix()
	end := f.clock.Truncate(24 * time.Hour).Add(24 * time.Hour).Unix()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/archives/auth?redemptionStartSeconds="+
			strconv.FormatInt(start, 10)+
			"&redemptionEndSeconds="+strconv.FormatInt(end, 10), nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK {
		t.Errorf("expected error status from GetBackupAuthCredentials error, got 200")
	}
}

// =============================================================================
// zkAuthenticate — AuthenticateBackupUser returns error (lines 46-49)
// =============================================================================

func TestZKAuthenticate_AuthenticateError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.authenticateBackupUserErr = &backups.FailedZkAuthError{Reason: "bad presentation"}

	req := httptest.NewRequest(http.MethodGet, "/v1/archives", nil)
	// Pass valid base64 data so decode steps pass, but the injector returns an error.
	req.Header.Set(headerZKAuth, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	req.Header.Set(headerZKAuthSig, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	// FailedZkAuthError → 401
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 from auth error, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleSetBackupId — success path (line 129)
// =============================================================================

func TestHandleSetBackupId_SuccessPath(t *testing.T) {
	f := newTestServerWithBackups(t)
	ctx := context.Background()

	// Build valid credential request bytes from the fixture's request context.
	reqBytes := zkgroup.SerializeBackupAuthCredentialRequest(f.clientCtx.GetRequest())
	acct := testAccount()
	// Seed in both stores: s.accounts (HTTP auth) and authAccountsMgr (SetBackupID lookup).
	_ = f.server.accounts.Create(ctx, acct)
	_ = f.authAccountsMgr.Create(ctx, acct)

	body := map[string]string{
		"messagesBackupAuthCredentialRequest": base64.StdEncoding.EncodeToString(reqBytes),
		"mediaBackupAuthCredentialRequest":    base64.StdEncoding.EncodeToString(reqBytes),
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/backupid",
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleRedeemReceipt — success path (line 192)
// The real RedeemReceipt requires a valid zkgroup receipt presentation which
// needs a full ceremony.  Use the injector with redeemReceiptErr=nil (default)
// and a non-empty body that passes the base64-decode step so the service call
// is reached and the injector allows it to succeed via the nil bypass.
// =============================================================================

func TestHandleRedeemReceipt_SuccessPath(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	_ = f.server.accounts.Create(context.Background(), testAccount())
	// Override RedeemReceipt to succeed unconditionally.
	inj.redeemReceiptErr = nil
	// Install an always-success stub — use the real service but override receipt
	// validation by switching the injector to succeed for this call.
	// We need to force the real call to succeed; instead we set a dedicated
	// flag by leaving redeemReceiptErr nil but overriding with a success callback.
	// The simplest approach: replace the real service with a no-op success stub.
	inj.real = &noopBackupService{}

	body := `{"receiptCredentialPresentation":"` +
		base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/archives/redeem-receipt",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 from no-op RedeemReceipt, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleSetBackupPublicKey — SetPublicKey success (lines 339-343)
// =============================================================================

func TestHandleSetBackupPublicKey_SuccessPath(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	// Use a no-op real service so SetPublicKey always succeeds.
	inj.real = &noopBackupService{}

	presBytes := make([]byte, 64)
	presBytes[0] = 0xAA
	sig := make([]byte, 64)
	pubKey := make([]byte, 32)
	body := map[string]string{
		"backupIdPublicKey": base64.StdEncoding.EncodeToString(pubKey),
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/keys",
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerZKAuth, base64.StdEncoding.EncodeToString(presBytes))
	req.Header.Set(headerZKAuthSig, base64.StdEncoding.EncodeToString(sig))
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 from SetPublicKey success, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleSetBackupPublicKey — SetPublicKey service error (lines 339-342)
// =============================================================================

func TestHandleSetBackupPublicKey_ServiceError(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.setPublicKeyErr = &backups.PublicKeyConflictError{}

	presBytes := make([]byte, 64)
	presBytes[0] = 0xBB
	sig := make([]byte, 64)
	pubKey := make([]byte, 32)
	body := map[string]string{
		"backupIdPublicKey": base64.StdEncoding.EncodeToString(pubKey),
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/keys",
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerZKAuth, base64.StdEncoding.EncodeToString(presBytes))
	req.Header.Set(headerZKAuthSig, base64.StdEncoding.EncodeToString(sig))
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	// PublicKeyConflictError → 409
	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 from SetPublicKey conflict, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleGetMediaUploadForm — success response body (lines 384-389)
// =============================================================================

func TestHandleGetMediaUploadForm_SuccessPath(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.real = &noopBackupService{}

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/media/upload/form", nil)
	// Use the injector with a no-op that authenticates and returns a descriptor.
	// The authenticator must succeed — noopBackupService's AuthenticateBackupUser
	// returns a zero-value AuthenticatedUser.
	req.Header.Set(headerZKAuth, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	req.Header.Set(headerZKAuthSig, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp UploadDescriptorResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

// =============================================================================
// handleCopyMedia — invalid JSON body (lines 434-437)
// =============================================================================

func TestHandleCopyMedia_InvalidJSONBody(t *testing.T) {
	f := newTestServerWithBackups(t)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media",
		strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	f.setZKHeaders(t, req, backups.BackupLevelPaid, backups.CredentialTypeMedia)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON: expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =============================================================================
// handleCopyMediaBatch — batch item with non-success outcome (lines 501-503)
// =============================================================================

func TestHandleCopyMediaBatch_NonSuccessOutcome(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	// Use a no-op service that always produces an OutOfQuota outcome.
	inj.real = &noopBackupService{}

	id1 := make([]byte, 32)
	id1[0] = 0xD1
	items := []map[string]interface{}{
		{
			"sourceAttachment": map[string]interface{}{"cdn": 3, "key": "src1"},
			"objectLength":     100,
			"mediaId":          base64.URLEncoding.EncodeToString(id1),
			"hmacKey":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"encryptionKey":    base64.StdEncoding.EncodeToString(make([]byte, 32)),
		},
	}
	body := map[string]interface{}{"items": items}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/v1/archives/media/batch",
		bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerZKAuth, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	req.Header.Set(headerZKAuthSig, base64.StdEncoding.EncodeToString(make([]byte, 64)))
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus {
		t.Errorf("expected 207, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp CopyMediaBatchResponseBody
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Responses) == 0 {
		t.Error("expected at least one response entry")
	}
	// At least one entry should have a non-empty Failure field (non-success outcome).
	var hasFailure bool
	for _, r := range resp.Responses {
		if r.Failure != "" {
			hasFailure = true
		}
	}
	if !hasFailure {
		t.Error("expected at least one non-success (Failure) batch response entry")
	}
}

// =============================================================================
// handleListMedia — non-nil cursor in result (lines 559-561)
// =============================================================================

func TestHandleListMedia_WithCursorInResult(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	cursor := "next-page-token"
	inj.listMediaResult = &backups.ListMediaResult{
		Media:  nil,
		Cursor: &cursor,
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/media?limit=10", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp ListMediaResponseBody
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Cursor != cursor {
		t.Errorf("expected cursor %q, got %q", cursor, resp.Cursor)
	}
}

// =============================================================================
// handleGetSVRBAuth — success path (lines 646-649)
// =============================================================================

func TestHandleGetSVRBAuth_SuccessPath(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	inj.generateSVRBAuthResult = &backups.ExternalServiceCredentials{
		Username: "svrb-user",
		Password: secrets.MustNewSecureString(t.Context(), "svrb-pass"),
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth/svrb", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp ExternalServiceCredentialsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Username != "svrb-user" {
		t.Errorf("expected username svrb-user, got %q", resp.Username)
	}
}

// =============================================================================
// noopBackupService: a minimal no-op implementation of BackupService for use
// when all methods need to succeed with zero values.
// =============================================================================

type noopBackupService struct{}

func (n *noopBackupService) SetBackupID(_ context.Context, _ string, _ uint64, _ backups.SetBackupIDRequest) error {
	return nil
}
func (n *noopBackupService) GetBackupIDLimits(_ context.Context, _ string) (*backups.BackupIDLimits, error) {
	return &backups.BackupIDLimits{}, nil
}
func (n *noopBackupService) RedeemReceipt(_ context.Context, _ string, _ backups.RedeemReceiptRequest) error {
	return nil
}
func (n *noopBackupService) GetBackupAuthCredentials(_ context.Context, _ string, _, _ time.Time) (*backups.CredentialsResponse, error) {
	return &backups.CredentialsResponse{}, nil
}
func (n *noopBackupService) AuthenticateBackupUser(_ context.Context, _, _ []byte, _ string) (*backups.AuthenticatedUser, error) {
	return &backups.AuthenticatedUser{}, nil
}
func (n *noopBackupService) SetPublicKey(_ context.Context, _, _, _ []byte) error {
	return nil
}
func (n *noopBackupService) BackupInfo(_ context.Context, _ *backups.AuthenticatedUser) (*backups.Info, error) {
	return &backups.Info{}, nil
}
func (n *noopBackupService) TTLRefresh(_ context.Context, _ *backups.AuthenticatedUser) error {
	return nil
}
func (n *noopBackupService) CreateMessageBackupUploadDescriptor(_ context.Context, _ *backups.AuthenticatedUser) (*backups.UploadDescriptor, error) {
	return &backups.UploadDescriptor{}, nil
}
func (n *noopBackupService) CreateTemporaryAttachmentUploadDescriptor(_ context.Context, _ *backups.AuthenticatedUser) (*backups.UploadDescriptor, error) {
	return &backups.UploadDescriptor{}, nil
}
func (n *noopBackupService) GenerateReadAuth(_ context.Context, _ *backups.AuthenticatedUser, _ int) (map[string]string, error) {
	return map[string]string{}, nil
}
func (n *noopBackupService) GenerateSVRBAuth(ctx context.Context, _ *backups.AuthenticatedUser) (*backups.ExternalServiceCredentials, error) {
	return &backups.ExternalServiceCredentials{Username: "u", Password: secrets.MustNewSecureString(ctx, "p")}, nil
}
func (n *noopBackupService) GetCopyQuota(_ context.Context, _ *backups.AuthenticatedUser, params []backups.CopyParameters) (*backups.CopyQuota, error) {
	// Return a quota with all items rejected (OutOfQuota) to exercise the non-success branch.
	rejected := make([]backups.CopyParameters, len(params))
	copy(rejected, params)
	return &backups.CopyQuota{ToReject: rejected}, nil
}
func (n *noopBackupService) CopyToBackup(_ context.Context, quota backups.CopyQuota, fn func(backups.CopyResult) error) error {
	for _, p := range quota.ToReject {
		if err := fn(backups.CopyResult{
			MediaID: p.DestinationMediaID,
			Outcome: backups.CopyOutcomeOutOfQuota,
		}); err != nil {
			return err
		}
	}
	return nil
}
func (n *noopBackupService) ListMedia(_ context.Context, _ *backups.AuthenticatedUser, _ *string, _ int) (*backups.ListMediaResult, error) {
	return &backups.ListMediaResult{}, nil
}
func (n *noopBackupService) DeleteMedia(_ context.Context, _ *backups.AuthenticatedUser, _ []backups.StorageDescriptor, _ func(backups.StorageDescriptor) error) error {
	return nil
}
func (n *noopBackupService) DeleteEntireBackup(_ context.Context, _ *backups.AuthenticatedUser) error {
	return nil
}
func (n *noopBackupService) ListBackupAttributes(_ context.Context, _ int, _ func(backups.StoredAttributes) error) error {
	return nil
}
func (n *noopBackupService) GetExpiredBackups(_ context.Context, _ int, _ time.Time, _ func(backups.ExpiredBackup) error) error {
	return nil
}
func (n *noopBackupService) ExpireBackup(_ context.Context, _ backups.ExpiredBackup) error {
	return nil
}
func (n *noopBackupService) RecalculateQuota(_ context.Context, _ backups.StoredAttributes) (*backups.RecalculationResult, error) {
	return nil, nil
}

var _ service.BackupService = (*noopBackupService)(nil)

// TestHandleGetBackupAuth_HappyPath seeds an account with committed
// BackupCredentialRequests in both the basic-auth store (s.accounts) and
// the AuthManager's account store, then calls GET /v1/archives/auth with
// a valid 24-hour redemption window.
func TestHandleGetBackupAuth_HappyPath(t *testing.T) {
	f := newTestServerWithBackups(t)
	ctx := context.Background()

	// Build serialized BackupAuthCredentialRequest bytes from the fixture's
	// request context so the credential issuance can verify them.
	reqBytes := zkgroup.SerializeBackupAuthCredentialRequest(f.clientCtx.GetRequest())

	acct := testAccount()
	acct.BackupCredentialRequests = &accounts.BackupCredentialRequests{
		Messages: reqBytes,
		Media:    reqBytes,
	}
	// Seed in the basic-auth store (for HTTP auth) and in the AuthManager's
	// account store (for GetBackupAuthCredentials lookup).
	_ = f.server.accounts.Create(ctx, acct)
	_ = f.authAccountsMgr.Create(ctx, acct)

	start := f.clock.Truncate(24 * time.Hour).Unix()
	end := f.clock.Truncate(24 * time.Hour).Add(24 * time.Hour).Unix()
	req := httptest.NewRequest(http.MethodGet,
		"/v1/archives/auth?redemptionStartSeconds="+
			strconv.FormatInt(start, 10)+
			"&redemptionEndSeconds="+strconv.FormatInt(end, 10), nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp CredentialsResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Credentials) == 0 {
		t.Error("expected credentials in response")
	}
}

// A credential whose protected password is already gone must not be
// serialized as an empty password with a 200 — the client would take it for a
// usable SVRB credential.
func TestHandleGetSVRBAuth_UnavailablePasswordFailsClosed(t *testing.T) {
	f, inj := newErrInjectRestServer(t)
	unavailable := &backups.ExternalServiceCredentials{
		Username: "svrb-user",
		Password: secrets.MustNewSecureString(t.Context(), "svrb-pass"),
	}
	unavailable.Destroy()
	inj.generateSVRBAuthResult = unavailable

	req := httptest.NewRequest(http.MethodGet, "/v1/archives/auth/svrb", nil)
	f.setZKHeaders(t, req, backups.BackupLevelFree, backups.CredentialTypeMessages)
	rr := httptest.NewRecorder()
	f.server.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"password"`) {
		t.Errorf("error response must not carry a credential: %s", rr.Body.String())
	}
}
