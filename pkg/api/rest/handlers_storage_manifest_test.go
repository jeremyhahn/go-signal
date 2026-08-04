package rest

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	"github.com/jeremyhahn/go-signal/pkg/securestorage/storagepb"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

// newStorageTestServer builds a minimal Server with the embedded storage
// service enabled (memory-backed) for exercising the real storage protocol.
func newStorageTestServer() *Server {
	mgr := securestorage.NewSecureStorageManager(testLogger())
	mgr.SetManifestStore(memory.NewMemoryManifestStore())
	return &Server{secureStorage: mgr, logger: testLogger()}
}

// --------------------------------------------------------------------------
// handleGetStorageManifestVersion
// --------------------------------------------------------------------------

func TestHandleGetStorageManifestVersion_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest/version/42", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetStorageManifestVersion_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	// Storage manifest routes now require account authentication (H11 fix).
	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest/version/1", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleGetStorageManifest_NoVersion(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// GET /storage/v1/storage/manifest (without version) should also return 204.
	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetStorageManifestVersion_ZeroVersion(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest/version/0", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetStorageManifestVersion_LargeVersion(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest/version/999999999", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestStorage_WriteGetReadRoundTrip exercises the full protobuf protocol path
// with the embedded storage service enabled.
func TestStorage_WriteGetReadRoundTrip(t *testing.T) {
	s := newStorageTestServer()
	const acct = "acct-x"
	ctx := contextWithAccount(context.Background(), &accounts.Account{UUID: acct})

	writeOp := &storagepb.WriteOperation{
		Manifest:   &storagepb.StorageManifest{Version: 1, Value: []byte("m1")},
		InsertItem: []*storagepb.StorageItem{{Key: []byte("k"), Value: []byte("v")}},
	}
	body, _ := proto.Marshal(writeOp)
	rr := httptest.NewRecorder()
	s.handleGetStorageManifestVersion(rr, httptest.NewRequest(http.MethodPut, "/storage/v1/storage", bytes.NewReader(body)).WithContext(ctx))
	if rr.Code != http.StatusOK {
		t.Fatalf("write: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	s.handleGetStorageManifestVersion(rr, httptest.NewRequest(http.MethodGet, "/storage/v1/storage/manifest", nil).WithContext(ctx))
	if rr.Code != http.StatusOK {
		t.Fatalf("get manifest: expected 200, got %d", rr.Code)
	}
	var manifest storagepb.StorageManifest
	if err := proto.Unmarshal(rr.Body.Bytes(), &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if manifest.Version != 1 || !bytes.Equal(manifest.Value, []byte("m1")) {
		t.Fatalf("unexpected manifest: %+v", &manifest)
	}

	readOp := &storagepb.ReadOperation{ReadKey: [][]byte{[]byte("k"), []byte("missing")}}
	rbody, _ := proto.Marshal(readOp)
	rr = httptest.NewRecorder()
	s.handleGetStorageManifestVersion(rr, httptest.NewRequest(http.MethodPut, "/storage/v1/storage/read", bytes.NewReader(rbody)).WithContext(ctx))
	if rr.Code != http.StatusOK {
		t.Fatalf("read: expected 200, got %d", rr.Code)
	}
	var items storagepb.StorageItems
	if err := proto.Unmarshal(rr.Body.Bytes(), &items); err != nil {
		t.Fatalf("unmarshal items: %v", err)
	}
	if len(items.Items) != 1 || !bytes.Equal(items.Items[0].Value, []byte("v")) {
		t.Fatalf("expected 1 item with value v, got %+v", items.Items)
	}
}

// TestStorage_WriteVersionConflictReturns409 confirms the optimistic-concurrency
// contract: a stale manifest version is rejected with 409 + the current manifest.
func TestStorage_WriteVersionConflictReturns409(t *testing.T) {
	s := newStorageTestServer()
	const acct = "acct-y"
	ctx := contextWithAccount(context.Background(), &accounts.Account{UUID: acct})

	write := func(version uint64, value string) *httptest.ResponseRecorder {
		op := &storagepb.WriteOperation{Manifest: &storagepb.StorageManifest{Version: version, Value: []byte(value)}}
		body, _ := proto.Marshal(op)
		rr := httptest.NewRecorder()
		s.handleGetStorageManifestVersion(rr, httptest.NewRequest(http.MethodPut, "/storage/v1/storage", bytes.NewReader(body)).WithContext(ctx))
		return rr
	}

	if rr := write(2, "v2"); rr.Code != http.StatusOK {
		t.Fatalf("first write: expected 200, got %d", rr.Code)
	}
	rr := write(2, "stale")
	if rr.Code != http.StatusConflict {
		t.Fatalf("stale write: expected 409, got %d", rr.Code)
	}
	var manifest storagepb.StorageManifest
	if err := proto.Unmarshal(rr.Body.Bytes(), &manifest); err != nil {
		t.Fatalf("unmarshal conflict manifest: %v", err)
	}
	if manifest.Version != 2 || !bytes.Equal(manifest.Value, []byte("v2")) {
		t.Fatalf("conflict should return current manifest v2, got %+v", &manifest)
	}
}
