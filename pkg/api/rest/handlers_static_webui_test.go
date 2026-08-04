package rest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ws "github.com/coder/websocket"

	"github.com/jeremyhahn/go-signal/pkg/attachments"
)

// --------------------------------------------------------------------------
// handleStaticResource
// --------------------------------------------------------------------------

func TestHandleStaticResource_NotConfigured(t *testing.T) {
	s := newTestServer(t)
	// staticResourcesDir is empty by default.

	req := httptest.NewRequest(http.MethodGet, "/static/some/file.txt", nil)
	rr := httptest.NewRecorder()
	// Use PathValue simulation by calling the handler directly via the mux.
	// The route uses {path...} so we need to invoke handleStaticResource directly
	// with a fabricated PathValue (not possible with httptest), so route via the
	// server mux with a registered URL pattern.
	// Instead call the method directly; PathValue returns "" when not invoked via
	// the stdlib mux, so we get the "missing path" branch.
	s.handleStaticResource(rr, req)

	// staticResourcesDir is "" → 404 with "static resources not configured"
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 when not configured, got %d", rr.Code)
	}
}

func TestHandleStaticResource_MissingPath(t *testing.T) {
	s := newTestServer(t)
	s.staticResourcesDir = t.TempDir()

	// PathValue("path") is "" because we call the handler directly, not via mux.
	req := httptest.NewRequest(http.MethodGet, "/static/", nil)
	rr := httptest.NewRecorder()
	s.handleStaticResource(rr, req)

	// PathValue returns "" → 400 "missing path"
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing path, got %d", rr.Code)
	}
}

func TestHandleStaticResource_FileNotFound(t *testing.T) {
	dir := t.TempDir()
	s := newTestServer(t)
	s.staticResourcesDir = dir

	// Build a real mux with the static route registered so PathValue works.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/{path...}", s.handleStaticResource)

	req := httptest.NewRequest(http.MethodGet, "/static/no-such-file.txt", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing file, got %d", rr.Code)
	}
}

func TestHandleStaticResource_ServeFile(t *testing.T) {
	dir := t.TempDir()
	content := []byte("static file content")
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), content, 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	s := newTestServer(t)
	s.staticResourcesDir = dir

	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/{path...}", s.handleStaticResource)

	req := httptest.NewRequest(http.MethodGet, "/static/hello.txt", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "static file content") {
		t.Errorf("expected file content in response, got %q", rr.Body.String())
	}
}

func TestHandleStaticResource_DirectoryTraversal(t *testing.T) {
	dir := t.TempDir()
	s := newTestServer(t)
	s.staticResourcesDir = dir

	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/{path...}", s.handleStaticResource)

	// A path like "../../etc/passwd" — after filepath.Clean it contains ".."
	req := httptest.NewRequest(http.MethodGet, "/static/../../etc/passwd", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// Either 400 (path contains ..) or 404 (outside root) is acceptable.
	if rr.Code == http.StatusOK {
		t.Errorf("directory traversal should not return 200")
	}
}

// --------------------------------------------------------------------------
// WebUIEventHub
// --------------------------------------------------------------------------

func TestNewWebUIEventHub_NotNil(t *testing.T) {
	h := NewWebUIEventHub()
	if h == nil {
		t.Fatal("NewWebUIEventHub returned nil")
	}
}

func TestWebUIEventHub_Broadcast_NoClients(t *testing.T) {
	h := NewWebUIEventHub()
	// Should not panic with zero clients.
	h.Broadcast("test-event", map[string]string{"key": "value"})
}

func TestWebUIEventHub_Broadcast_UnmarshalablePayload(t *testing.T) {
	h := NewWebUIEventHub()
	// json.Marshal of a channel always fails; Broadcast must not panic.
	ch := make(chan struct{})
	h.Broadcast("bad-event", ch)
}

func TestWebUIEventHub_RegisterRoute(t *testing.T) {
	h := NewWebUIEventHub()
	mux := http.NewServeMux()
	// RegisterRoute must not panic.
	h.RegisterRoute(mux)
}

func TestWebUIEventHub_HandleWebSocket_NonWSRequest(t *testing.T) {
	h := NewWebUIEventHub()

	// A plain HTTP request (not a WebSocket upgrade) causes ws.Accept to fail;
	// the handler should return without panicking.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	rr := httptest.NewRecorder()
	h.HandleWebSocket(rr, req)

	// ws.Accept fails; handler returns with no 101.
	if rr.Code == http.StatusSwitchingProtocols {
		t.Error("expected non-101 for plain HTTP request")
	}
}

func TestWebUIEventHub_HandleWebSocket_FullLifecycle(t *testing.T) {
	h := NewWebUIEventHub()

	srv := httptest.NewServer(http.HandlerFunc(h.HandleWebSocket))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/events"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}

	// Broadcast to the connected client (should not panic).
	h.Broadcast("msg-received", map[string]string{"from": "tester"})

	// Close the connection to unblock the server-side CloseRead.
	_ = conn.Close(ws.StatusNormalClosure, "done")
}

// --------------------------------------------------------------------------
// Server.SetAttachmentStore
// --------------------------------------------------------------------------

func TestServer_SetAttachmentStore(t *testing.T) {
	s := newTestServer(t)
	if s.attachmentStore != nil {
		t.Error("expected nil attachment store initially")
	}

	store := &stubAttachmentStore{}
	s.SetAttachmentStore(store)

	if s.attachmentStore == nil {
		t.Error("expected non-nil attachment store after SetAttachmentStore")
	}
}

// stubAttachmentStore is a minimal no-op attachments.Store for testing.
type stubAttachmentStore struct{}

var _ attachments.Store = (*stubAttachmentStore)(nil)

func (s *stubAttachmentStore) Put(_ context.Context, _ string, _ io.Reader, _ int64) error {
	return nil
}

func (s *stubAttachmentStore) Get(_ context.Context, _ string) (io.ReadCloser, int64, error) {
	return io.NopCloser(strings.NewReader("")), 0, nil
}

func (s *stubAttachmentStore) Delete(_ context.Context, _ string) error { return nil }

func (s *stubAttachmentStore) Exists(_ context.Context, _ string) (bool, error) { return false, nil }

// --------------------------------------------------------------------------
// handleCDNDownload
// --------------------------------------------------------------------------

func TestHandleCDNDownload_NoAttachmentStore(t *testing.T) {
	s := newTestServer(t)
	// attachmentStore is nil by default → 404.

	req := httptest.NewRequest(http.MethodGet, "/cdn3/some-key", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 when no store configured, got %d", rr.Code)
	}
}

func TestHandleCDNDownload_MissingKey(t *testing.T) {
	s := newTestServer(t)
	s.attachmentStore = &stubAttachmentStore{}

	// Call the handler directly so PathValue("rest") returns "".
	req := httptest.NewRequest(http.MethodGet, "/cdn3/", nil)
	rr := httptest.NewRecorder()
	s.handleCDNDownload(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing key, got %d", rr.Code)
	}
}

func TestHandleCDNDownload_NotFound(t *testing.T) {
	s := newTestServer(t)
	s.attachmentStore = &errorAttachmentStore{}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /cdn3/{rest...}", s.handleCDNDownload)

	req := httptest.NewRequest(http.MethodGet, "/cdn3/missing-file", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing file, got %d", rr.Code)
	}
}

func TestHandleCDNDownload_Success(t *testing.T) {
	s := newTestServer(t)
	s.attachmentStore = &dataAttachmentStore{data: "hello attachment"}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /cdn3/{rest...}", s.handleCDNDownload)

	req := httptest.NewRequest(http.MethodGet, "/cdn3/my-file-key", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "hello attachment" {
		t.Errorf("expected body %q, got %q", "hello attachment", rr.Body.String())
	}
}

// errorAttachmentStore always returns an error from Get.
type errorAttachmentStore struct{ stubAttachmentStore }

func (e *errorAttachmentStore) Get(_ context.Context, _ string) (io.ReadCloser, int64, error) {
	return nil, 0, errors.New("not found")
}

// dataAttachmentStore returns a fixed data payload from Get.
type dataAttachmentStore struct {
	stubAttachmentStore
	data string
}

func (d *dataAttachmentStore) Get(_ context.Context, _ string) (io.ReadCloser, int64, error) {
	r := strings.NewReader(d.data)
	return io.NopCloser(r), int64(r.Len()), nil
}

// --------------------------------------------------------------------------
// middleware.requireNotAuthenticated
// --------------------------------------------------------------------------

func TestRequireNotAuthenticated_WithBasicAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("user", "pass")
	rr := httptest.NewRecorder()

	ok := requireNotAuthenticated(rr, req)
	if ok {
		t.Error("expected false (rejected) when Basic Auth is present")
	}
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestRequireNotAuthenticated_WithoutAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	ok := requireNotAuthenticated(rr, req)
	if !ok {
		t.Error("expected true (allowed) when no Basic Auth")
	}
}
