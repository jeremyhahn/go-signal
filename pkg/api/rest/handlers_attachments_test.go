package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/auth/external"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func TestHandleAttachmentUploadForm_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v4/attachments/form/upload", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp AttachmentDescriptorV3
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.CDN != 3 {
		t.Errorf("expected CDN 3, got %d", resp.CDN)
	}
	if resp.Key == "" {
		t.Error("expected non-empty key")
	}
	if resp.SignedUploadLocation == "" {
		t.Error("expected non-empty upload location")
	}
}

func TestHandleAttachmentUploadForm_ExternalTUS_AttachesBasicAuth(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	gen, err := external.NewGenerator(external.GeneratorConfig{Key: secrets.MustNewSecureString("tus-secret")})
	if err != nil {
		t.Fatalf("external.NewGenerator: %v", err)
	}
	s.SetAttachmentTus("https://tus.signal.test", gen)

	req := httptest.NewRequest(http.MethodGet, "/v4/attachments/form/upload", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp AttachmentDescriptorV3
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.SignedUploadLocation != "https://tus.signal.test/attachments" {
		t.Errorf("upload location = %q", resp.SignedUploadLocation)
	}
	auth := resp.Headers["Authorization"]
	if !strings.HasPrefix(auth, "Basic ") {
		t.Fatalf("missing Basic auth header: %q", auth)
	}
	rawAuth, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		t.Fatalf("decode Basic: %v", err)
	}
	parts := strings.SplitN(string(rawAuth), ":", 2)
	if len(parts) != 2 {
		t.Fatalf("Basic value malformed: %q", rawAuth)
	}
	if !strings.HasPrefix(parts[0], "attachments/") {
		t.Errorf("username = %q, want attachments/<key>", parts[0])
	}
	if resp.Headers["Upload-Metadata"] == "" {
		t.Error("Upload-Metadata header missing")
	}
}

func TestHandleAttachmentUploadForm_NoTUSFallsBackToEmbeddedCDN(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	// Sanity: no TUS configured -> Location header absent, URL points at /cdn3.
	req := httptest.NewRequest(http.MethodGet, "/v4/attachments/form/upload", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp AttachmentDescriptorV3
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !strings.Contains(resp.SignedUploadLocation, "/cdn3/attachments/") {
		t.Errorf("embedded-CDN URL expected, got %q", resp.SignedUploadLocation)
	}
	if _, ok := resp.Headers["Authorization"]; ok {
		t.Error("Authorization header must be absent in embedded-CDN mode")
	}
}

func TestHandleAttachmentUploadForm_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v4/attachments/form/upload", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// CDN/TUS upload handlers
// --------------------------------------------------------------------------

func TestHandleCDNUpload_POST_ReturnsCreatedWithLocation(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/cdn3/attachments/test-key", strings.NewReader("initial data"))
	req.Header.Set("Upload-Length", "1024")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	location := rr.Header().Get("Location")
	if location == "" {
		t.Error("expected Location header")
	}
	if !strings.Contains(location, "/cdn3/upload/") {
		t.Errorf("expected Location to contain /cdn3/upload/, got %q", location)
	}

	tusVersion := rr.Header().Get("Tus-Resumable")
	if tusVersion != "1.0.0" {
		t.Errorf("expected Tus-Resumable 1.0.0, got %q", tusVersion)
	}

	offset := rr.Header().Get("Upload-Offset")
	if offset != "0" {
		t.Errorf("expected Upload-Offset 0, got %q", offset)
	}
}

func TestHandleCDNUpload_POST_NoBody(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/cdn3/attachments/test-key", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}

	if rr.Header().Get("Location") == "" {
		t.Error("expected Location header even with no body")
	}
}

func TestHandleCDNUpload_PATCH_ReturnsNoContentWithOffset(t *testing.T) {
	s := newTestServer(t)

	body := "hello world upload data"
	req := httptest.NewRequest(http.MethodPatch, "/cdn3/upload/session-123", strings.NewReader(body))
	req.Header.Set("Upload-Offset", "100")
	req.Header.Set("Content-Type", "application/offset+octet-stream")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	expectedOffset := 100 + len(body)
	gotOffset := rr.Header().Get("Upload-Offset")
	if gotOffset != strconv.Itoa(expectedOffset) {
		t.Errorf("expected Upload-Offset %d, got %q", expectedOffset, gotOffset)
	}

	tusVersion := rr.Header().Get("Tus-Resumable")
	if tusVersion != "1.0.0" {
		t.Errorf("expected Tus-Resumable 1.0.0, got %q", tusVersion)
	}
}

func TestHandleCDNUpload_PATCH_NoUploadOffsetHeader(t *testing.T) {
	s := newTestServer(t)

	body := "data chunk"
	req := httptest.NewRequest(http.MethodPatch, "/cdn3/upload/session-456", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Without Upload-Offset header, start offset defaults to 0.
	gotOffset := rr.Header().Get("Upload-Offset")
	if gotOffset != strconv.Itoa(len(body)) {
		t.Errorf("expected Upload-Offset %d, got %q", len(body), gotOffset)
	}
}

func TestHandleCDNUpload_HEAD_ReturnsUploadStatus(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodHead, "/cdn3/upload/session-789", nil)
	req.Header.Set("Upload-Length", "2048")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if rr.Header().Get("Upload-Length") != "2048" {
		t.Errorf("expected Upload-Length 2048, got %q", rr.Header().Get("Upload-Length"))
	}
	if rr.Header().Get("Upload-Offset") != "2048" {
		t.Errorf("expected Upload-Offset 2048, got %q", rr.Header().Get("Upload-Offset"))
	}
	if rr.Header().Get("Tus-Resumable") != "1.0.0" {
		t.Errorf("expected Tus-Resumable 1.0.0, got %q", rr.Header().Get("Tus-Resumable"))
	}
}

func TestHandleCDNUpload_HEAD_NoUploadLengthHeader(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodHead, "/cdn3/upload/session-abc", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Without Upload-Length header, defaults to "0".
	if rr.Header().Get("Upload-Length") != "0" {
		t.Errorf("expected Upload-Length 0, got %q", rr.Header().Get("Upload-Length"))
	}
	if rr.Header().Get("Upload-Offset") != "0" {
		t.Errorf("expected Upload-Offset 0, got %q", rr.Header().Get("Upload-Offset"))
	}
}

func TestHandleCDNUpload_PUT_ReturnsOK(t *testing.T) {
	s := newTestServer(t)

	body := "direct upload content"
	req := httptest.NewRequest(http.MethodPut, "/cdn3/attachments/direct-key", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCDNUpload_PUT_EmptyBody(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/cdn3/attachments/empty-key", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCDNUpload_UnsupportedMethod(t *testing.T) {
	s := newTestServer(t)

	// Call handleCDNUpload directly with DELETE to hit the default case,
	// since the mux only registers PUT/POST/PATCH/HEAD.
	req := httptest.NewRequest(http.MethodDelete, "/cdn3/attachments/test-key", nil)
	rr := httptest.NewRecorder()
	s.handleCDNUpload(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleCDNUpload_CDN2Route(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/cdn2/attachments/test-key", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201 on cdn2 route, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCDNUpload_CDNRoute(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/cdn/attachments/test-key", strings.NewReader("data"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on cdn route, got %d: %s", rr.Code, rr.Body.String())
	}
}

// errReader is a ReadCloser that always returns an error on Read, used to
// exercise error paths in handlers that read the request body.
type errReader struct{ err error }

func (e *errReader) Read(_ []byte) (int, error) { return 0, e.err }
func (e *errReader) Close() error               { return nil }

func TestHandleCDNUploadPut_ReadError_Returns500(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/cdn3/attachments/error-key", nil)
	// PathValue is normally populated by the mux; set it explicitly for the
	// direct handler call so the key passes validation and the read-error
	// path is exercised.
	req.SetPathValue("rest", "attachments/error-key")
	req.Body = &errReader{err: errors.New("simulated read error")}
	rr := httptest.NewRecorder()
	s.handleCDNUploadPut(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on read error, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCDNUploadCreate_ReadError_Returns500(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/cdn3/attachments/error-key", nil)
	req.Body = &errReader{err: errors.New("simulated read error")}
	rr := httptest.NewRecorder()
	s.handleCDNUploadCreate(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on read error, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// memAttachmentStore: in-memory attachments.Store for testing the
// s.attachmentStore != nil branches in handleCDNUploadPatch/Put.
// --------------------------------------------------------------------------

type memAttachmentStore struct {
	blobs     map[string][]byte
	existsErr error
	putErr    error
}

func newMemAttachmentStore() *memAttachmentStore {
	return &memAttachmentStore{blobs: make(map[string][]byte)}
}

func (s *memAttachmentStore) Put(ctx context.Context, key string, data io.Reader, size int64) error {
	if s.putErr != nil {
		return s.putErr
	}
	b, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	s.blobs[key] = b
	return nil
}

func (s *memAttachmentStore) Get(_ context.Context, key string) (io.ReadCloser, int64, error) {
	b, ok := s.blobs[key]
	if !ok {
		return nil, 0, errors.New("not found")
	}
	return io.NopCloser(strings.NewReader(string(b))), int64(len(b)), nil
}

func (s *memAttachmentStore) Delete(_ context.Context, key string) error {
	delete(s.blobs, key)
	return nil
}

func (s *memAttachmentStore) Exists(_ context.Context, key string) (bool, error) {
	if s.existsErr != nil {
		return false, s.existsErr
	}
	_, ok := s.blobs[key]
	return ok, nil
}

// --------------------------------------------------------------------------
// handleCDNUploadPatch with attachment store
// --------------------------------------------------------------------------

func TestHandleCDNUploadPatch_WithStore_NewKey(t *testing.T) {
	s := newTestServer(t)
	store := newMemAttachmentStore()
	s.SetAttachmentStore(store)

	body := "upload chunk data"
	req := httptest.NewRequest(http.MethodPatch, "/cdn3/upload/new-key", strings.NewReader(body))
	req.Header.Set("Upload-Length", strconv.Itoa(len(body)))
	req.SetPathValue("rest", "upload/new-key")
	rr := httptest.NewRecorder()
	s.handleCDNUploadPatch(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCDNUploadPatch_WithStore_AlreadyExists_Conflict(t *testing.T) {
	s := newTestServer(t)
	store := newMemAttachmentStore()
	// Pre-populate so Exists returns true.
	store.blobs["upload/existing-key"] = []byte("already here")
	s.SetAttachmentStore(store)

	req := httptest.NewRequest(http.MethodPatch, "/cdn3/upload/existing-key", strings.NewReader("data"))
	req.SetPathValue("rest", "upload/existing-key")
	rr := httptest.NewRecorder()
	s.handleCDNUploadPatch(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCDNUploadPatch_WithStore_ExistsError(t *testing.T) {
	s := newTestServer(t)
	store := newMemAttachmentStore()
	store.existsErr = errors.New("storage unavailable")
	s.SetAttachmentStore(store)

	req := httptest.NewRequest(http.MethodPatch, "/cdn3/upload/err-key", strings.NewReader("data"))
	req.SetPathValue("rest", "upload/err-key")
	rr := httptest.NewRecorder()
	s.handleCDNUploadPatch(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCDNUploadPatch_WithStore_PutError(t *testing.T) {
	s := newTestServer(t)
	store := newMemAttachmentStore()
	store.putErr = errors.New("put failed")
	s.SetAttachmentStore(store)

	req := httptest.NewRequest(http.MethodPatch, "/cdn3/upload/put-err-key", strings.NewReader("data"))
	req.Header.Set("Upload-Length", "4")
	req.SetPathValue("rest", "upload/put-err-key")
	rr := httptest.NewRecorder()
	s.handleCDNUploadPatch(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCDNUploadPatch_WithStore_WithOffset(t *testing.T) {
	// Non-zero offset: Exists check is skipped, put proceeds directly.
	s := newTestServer(t)
	store := newMemAttachmentStore()
	// Key already exists but offset is non-zero so conflict check is skipped.
	store.blobs["upload/offset-key"] = []byte("initial data")
	s.SetAttachmentStore(store)

	body := "more data"
	req := httptest.NewRequest(http.MethodPatch, "/cdn3/upload/offset-key", strings.NewReader(body))
	req.Header.Set("Upload-Offset", "12") // start at byte 12
	req.Header.Set("Upload-Length", strconv.Itoa(len(body)))
	req.SetPathValue("rest", "upload/offset-key")
	rr := httptest.NewRecorder()
	s.handleCDNUploadPatch(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for offset upload, got %d: %s", rr.Code, rr.Body.String())
	}
	offset, _ := strconv.Atoi(rr.Header().Get("Upload-Offset"))
	if offset != 12+len(body) {
		t.Errorf("expected offset %d, got %d", 12+len(body), offset)
	}
}

// --------------------------------------------------------------------------
// handleCDNUploadPut with attachment store
// --------------------------------------------------------------------------

func TestHandleCDNUploadPut_WithStore_Success(t *testing.T) {
	s := newTestServer(t)
	store := newMemAttachmentStore()
	s.SetAttachmentStore(store)

	body := "direct put content"
	req := httptest.NewRequest(http.MethodPut, "/cdn3/attachments/new-key", strings.NewReader(body))
	req.SetPathValue("rest", "attachments/new-key")
	rr := httptest.NewRecorder()
	s.handleCDNUploadPut(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if string(store.blobs["attachments/new-key"]) != body {
		t.Errorf("expected stored body %q, got %q", body, string(store.blobs["attachments/new-key"]))
	}
}

func TestHandleCDNUploadPut_WithStore_AlreadyExists_Conflict(t *testing.T) {
	s := newTestServer(t)
	store := newMemAttachmentStore()
	store.blobs["attachments/dup-key"] = []byte("existing")
	s.SetAttachmentStore(store)

	req := httptest.NewRequest(http.MethodPut, "/cdn3/attachments/dup-key", strings.NewReader("new"))
	req.SetPathValue("rest", "attachments/dup-key")
	rr := httptest.NewRecorder()
	s.handleCDNUploadPut(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCDNUploadPut_WithStore_ExistsError(t *testing.T) {
	s := newTestServer(t)
	store := newMemAttachmentStore()
	store.existsErr = errors.New("backend failure")
	s.SetAttachmentStore(store)

	req := httptest.NewRequest(http.MethodPut, "/cdn3/attachments/err-key", strings.NewReader("data"))
	req.SetPathValue("rest", "attachments/err-key")
	rr := httptest.NewRecorder()
	s.handleCDNUploadPut(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCDNUploadPut_WithStore_PutError(t *testing.T) {
	s := newTestServer(t)
	store := newMemAttachmentStore()
	store.putErr = errors.New("put failed")
	s.SetAttachmentStore(store)

	req := httptest.NewRequest(http.MethodPut, "/cdn3/attachments/put-err-key", strings.NewReader("data"))
	req.SetPathValue("rest", "attachments/put-err-key")
	rr := httptest.NewRecorder()
	s.handleCDNUploadPut(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestIsSafeCDNKey_DotSegment(t *testing.T) {
	// ".." segment must be rejected.
	if isSafeCDNKey("..") {
		t.Error("expected '..' to be unsafe")
	}
	if isSafeCDNKey(".") {
		t.Error("expected '.' to be unsafe")
	}
	// But a key with a non-dot segment is fine.
	if !isSafeCDNKey("attachments/valid-key") {
		t.Error("expected 'attachments/valid-key' to be safe")
	}
}
