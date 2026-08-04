package rest

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	"github.com/jeremyhahn/go-signal/pkg/securestorage/storagepb"
	"github.com/jeremyhahn/go-signal/pkg/service"
	storagememory "github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

// errStorage is a sentinel error used in storage service stubs.
var errStorage = errors.New("storage service error")

// stubSecureStorageService implements service.SecureStorageService with
// configurable behaviour for unit testing error paths.
type stubSecureStorageService struct {
	enabled        bool
	manifest       *securestorage.StorageManifest
	items          []*securestorage.StorageItem
	getManifestErr error
	writeErr       error
	readErr        error
	authErr        error
}

func (s *stubSecureStorageService) StorageEnabled() bool { return s.enabled }

func (s *stubSecureStorageService) GetManifest(_ context.Context, _ string) (*securestorage.StorageManifest, error) {
	if s.getManifestErr != nil {
		return nil, s.getManifestErr
	}
	return s.manifest, nil
}

func (s *stubSecureStorageService) Write(_ context.Context, _ string, _ *securestorage.StorageManifest, _ []*securestorage.StorageItem, _ [][]byte, _ bool) (*securestorage.StorageManifest, error) {
	if s.writeErr != nil {
		return nil, s.writeErr
	}
	return nil, nil
}

func (s *stubSecureStorageService) Read(_ context.Context, _ string, _ [][]byte) ([]*securestorage.StorageItem, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	return s.items, nil
}

func (s *stubSecureStorageService) GetAuth(_ context.Context, accountUUID string) (*securestorage.StorageCredentials, error) {
	if s.authErr != nil {
		return nil, s.authErr
	}
	return &securestorage.StorageCredentials{Username: accountUUID, Password: "pwd"}, nil
}

// compile-time interface check.
var _ service.SecureStorageService = (*stubSecureStorageService)(nil)

// newStorageTestServerWithStub creates a bare Server with the given
// SecureStorageService stub (no routing — call handler methods directly).
func newStorageTestServerWithStub(svc service.SecureStorageService) *Server {
	return &Server{secureStorage: svc, logger: testLogger()}
}

// newStorageTestServerWithMemory creates a Server backed by an in-memory
// manifest store so the real storage-service protocol can be exercised without
// routing through the HTTP mux.
func newStorageTestServerWithMemory() *Server {
	mgr := securestorage.NewSecureStorageManager(testLogger())
	mgr.SetManifestStore(storagememory.NewMemoryManifestStore())
	return &Server{secureStorage: mgr, logger: testLogger()}
}

// ctxWithAcct wraps a background context with the given account so handlers
// can extract it via accountFromContext.
func ctxWithAcct(uuid string) context.Context {
	return contextWithAccount(context.Background(), &accounts.Account{UUID: uuid})
}

// --------------------------------------------------------------------------
// handleGetStorageManifestVersion — default case
// --------------------------------------------------------------------------

func TestHandleGetStorageManifestVersion_DefaultCaseReturns204(t *testing.T) {
	s := newStorageTestServerWithMemory()
	ctx := ctxWithAcct("acct-default")

	// DELETE is not handled by any explicit case and falls through to default.
	req := httptest.NewRequest(http.MethodDelete, "/storage/v1/storage", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleGetStorageManifestVersion(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for default case, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetStorageManifestVersion — storage enabled but no account in context → 401
// --------------------------------------------------------------------------

func TestHandleGetStorageManifestVersion_StorageEnabledNoAccountReturns401(t *testing.T) {
	s := newStorageTestServerWithMemory()

	// Call handler directly with no account in context.
	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest", nil)
	// context has no account (background context).
	rr := httptest.NewRecorder()
	s.handleGetStorageManifestVersion(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when no account in context, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetStorageManifestVersion — storage disabled
// --------------------------------------------------------------------------

func TestHandleGetStorageManifestVersion_StorageDisabledReturns204(t *testing.T) {
	s := newStorageTestServerWithStub(&stubSecureStorageService{enabled: false})
	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest", nil)
	rr := httptest.NewRecorder()
	s.handleGetStorageManifestVersion(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 when storage disabled, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleStorageGetManifest — error path
// --------------------------------------------------------------------------

func TestHandleStorageGetManifest_StoreErrorReturns500(t *testing.T) {
	svc := &stubSecureStorageService{
		enabled:        true,
		getManifestErr: errStorage,
	}
	s := newStorageTestServerWithStub(svc)
	ctx := ctxWithAcct("acct-err")

	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleGetStorageManifestVersion(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on store error, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleStorageGetManifest — nil manifest (204) with storage enabled
// --------------------------------------------------------------------------

func TestHandleStorageGetManifest_NilManifestWithStorageEnabledReturns204(t *testing.T) {
	svc := &stubSecureStorageService{
		enabled:  true,
		manifest: nil, // no manifest stored yet
	}
	s := newStorageTestServerWithStub(svc)
	ctx := ctxWithAcct("acct-nil")

	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleGetStorageManifestVersion(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for nil manifest, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleStorageGetManifest — version check: server manifest is newer
// --------------------------------------------------------------------------

func TestHandleStorageGetManifest_ServerManifestNewerThanClientVersion(t *testing.T) {
	// Server manifest is at version 10, client supplies version 5.
	// The server should return the full manifest (200).
	s := newStorageTestServerWithMemory()
	ctx := ctxWithAcct("acct-newer")

	// Write version 10.
	writeOp := &storagepb.WriteOperation{
		Manifest: &storagepb.StorageManifest{Version: 10, Value: []byte("v10")},
	}
	body, _ := proto.Marshal(writeOp)
	rr := httptest.NewRecorder()
	s.handleGetStorageManifestVersion(rr,
		httptest.NewRequest(http.MethodPut, "/storage/v1/storage", bytes.NewReader(body)).WithContext(ctx))
	if rr.Code != http.StatusOK {
		t.Fatalf("write v10: expected 200, got %d", rr.Code)
	}

	// GET manifest/version/5 — server (10) is newer than client (5) → return manifest.
	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest/version/5", nil).WithContext(ctx)
	req.SetPathValue("version", "5")
	rr = httptest.NewRecorder()
	s.handleStorageGetManifest(rr, req, "acct-newer")

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 (server newer), got %d: %s", rr.Code, rr.Body.String())
	}
	var m storagepb.StorageManifest
	if err := proto.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.Version != 10 {
		t.Errorf("expected version 10, got %d", m.Version)
	}
}

// --------------------------------------------------------------------------
// handleStorageGetManifest — version check: same version → 204
// --------------------------------------------------------------------------

func TestHandleStorageGetManifest_SameVersionReturns204(t *testing.T) {
	s := newStorageTestServerWithMemory()
	ctx := ctxWithAcct("acct-same")

	writeOp := &storagepb.WriteOperation{
		Manifest: &storagepb.StorageManifest{Version: 3, Value: []byte("v3")},
	}
	body, _ := proto.Marshal(writeOp)
	rr := httptest.NewRecorder()
	s.handleGetStorageManifestVersion(rr,
		httptest.NewRequest(http.MethodPut, "/storage/v1/storage", bytes.NewReader(body)).WithContext(ctx))
	if rr.Code != http.StatusOK {
		t.Fatalf("write v3: expected 200, got %d", rr.Code)
	}

	// GET manifest/version/3 — server version 3 == client version 3 → 204.
	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest/version/3", nil).WithContext(ctx)
	req.SetPathValue("version", "3")
	rr = httptest.NewRecorder()
	s.handleStorageGetManifest(rr, req, "acct-same")

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for same version, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleStorageGetManifest — no version in URL → returns manifest (200)
// --------------------------------------------------------------------------

func TestHandleStorageGetManifest_NoVersionReturnsManifest(t *testing.T) {
	s := newStorageTestServerWithMemory()
	ctx := ctxWithAcct("acct-noversion")

	writeOp := &storagepb.WriteOperation{
		Manifest: &storagepb.StorageManifest{Version: 7, Value: []byte("v7")},
	}
	body, _ := proto.Marshal(writeOp)
	rr := httptest.NewRecorder()
	s.handleGetStorageManifestVersion(rr,
		httptest.NewRequest(http.MethodPut, "/storage/v1/storage", bytes.NewReader(body)).WithContext(ctx))
	if rr.Code != http.StatusOK {
		t.Fatalf("write v7: expected 200, got %d", rr.Code)
	}

	// GET manifest without version segment → always returns manifest (200).
	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest", nil).WithContext(ctx)
	rr = httptest.NewRecorder()
	s.handleStorageGetManifest(rr, req, "acct-noversion")

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for no-version GET, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleStorageWrite — nil manifest in write operation → 400
// --------------------------------------------------------------------------

func TestHandleStorageWrite_NilManifestReturns400(t *testing.T) {
	s := newStorageTestServerWithMemory()
	ctx := ctxWithAcct("acct-nil-mf")

	// WriteOperation with no manifest set.
	op := &storagepb.WriteOperation{}
	body, _ := proto.Marshal(op)

	req := httptest.NewRequest(http.MethodPut, "/storage/v1/storage", bytes.NewReader(body)).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleStorageWrite(rr, req, "acct-nil-mf")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for nil manifest, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleStorageWrite — invalid protobuf body → 400
// --------------------------------------------------------------------------

func TestHandleStorageWrite_InvalidProtobufReturns400(t *testing.T) {
	s := newStorageTestServerWithMemory()
	ctx := ctxWithAcct("acct-bad-proto")

	req := httptest.NewRequest(http.MethodPut, "/storage/v1/storage",
		bytes.NewReader([]byte{0xFF, 0xFE, 0xFD})).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleStorageWrite(rr, req, "acct-bad-proto")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid protobuf, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleStorageWrite — Write returns error → 500
// --------------------------------------------------------------------------

func TestHandleStorageWrite_WriteErrorReturns500(t *testing.T) {
	svc := &stubSecureStorageService{
		enabled:  true,
		writeErr: errStorage,
	}
	s := newStorageTestServerWithStub(svc)
	ctx := ctxWithAcct("acct-write-err")

	op := &storagepb.WriteOperation{
		Manifest: &storagepb.StorageManifest{Version: 1, Value: []byte("v1")},
	}
	body, _ := proto.Marshal(op)
	req := httptest.NewRequest(http.MethodPut, "/storage/v1/storage", bytes.NewReader(body)).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleStorageWrite(rr, req, "acct-write-err")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on write error, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleStorageWrite — body read error → 400
// --------------------------------------------------------------------------

func TestHandleStorageWrite_BodyReadErrorReturns400(t *testing.T) {
	s := newStorageTestServerWithMemory()
	ctx := ctxWithAcct("acct-body-err")

	req := httptest.NewRequest(http.MethodPut, "/storage/v1/storage", nil).WithContext(ctx)
	req.Body = &errReader{err: errors.New("simulated read error")}
	rr := httptest.NewRecorder()
	s.handleStorageWrite(rr, req, "acct-body-err")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on body read error, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleStorageRead — invalid protobuf body → 400
// --------------------------------------------------------------------------

func TestHandleStorageRead_InvalidProtobufReturns400(t *testing.T) {
	s := newStorageTestServerWithMemory()
	ctx := ctxWithAcct("acct-bad-read")

	req := httptest.NewRequest(http.MethodPut, "/storage/v1/storage/read",
		bytes.NewReader([]byte{0xFF, 0xFE, 0xFD})).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleStorageRead(rr, req, "acct-bad-read")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid protobuf in read, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleStorageRead — Read returns error → 500
// --------------------------------------------------------------------------

func TestHandleStorageRead_ReadErrorReturns500(t *testing.T) {
	svc := &stubSecureStorageService{
		enabled: true,
		readErr: errStorage,
	}
	s := newStorageTestServerWithStub(svc)
	ctx := ctxWithAcct("acct-read-err")

	op := &storagepb.ReadOperation{ReadKey: [][]byte{[]byte("k")}}
	body, _ := proto.Marshal(op)
	req := httptest.NewRequest(http.MethodPut, "/storage/v1/storage/read",
		bytes.NewReader(body)).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleStorageRead(rr, req, "acct-read-err")

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on read error, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleStorageRead — body read error → 400
// --------------------------------------------------------------------------

func TestHandleStorageRead_BodyReadErrorReturns400(t *testing.T) {
	s := newStorageTestServerWithMemory()
	ctx := ctxWithAcct("acct-read-body-err")

	req := httptest.NewRequest(http.MethodPut, "/storage/v1/storage/read", nil).WithContext(ctx)
	req.Body = &errReader{err: errors.New("simulated read error")}
	rr := httptest.NewRecorder()
	s.handleStorageRead(rr, req, "acct-read-body-err")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on body read error, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetStorageAuth — GetAuth error path → 500
// --------------------------------------------------------------------------

func TestHandleGetStorageAuth_AuthErrorReturns500(t *testing.T) {
	svc := &stubSecureStorageService{
		enabled: true,
		authErr: errStorage,
	}
	s := newStorageTestServerWithStub(svc)
	ctx := ctxWithAcct("acct-auth-err")

	req := httptest.NewRequest(http.MethodGet, "/v1/storage/auth", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	s.handleGetStorageAuth(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on GetAuth error, got %d: %s", rr.Code, rr.Body.String())
	}
}
