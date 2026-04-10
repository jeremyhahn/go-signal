package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
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
