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

	req := httptest.NewRequest(http.MethodGet, "/static/../../etc/passwd", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// This exercises the route COMPOSITION, and the handler is never reached:
	// ServeMux normalises the path and answers 307 to /etc/passwd before
	// PathValue exists. Measured, not assumed — an earlier version of this
	// test asserted only "not 200" and had been passing on that redirect,
	// which means it would equally have passed against a handler with no guard
	// at all.
	//
	// So the assertion stays deliberately broad — no 2xx, no file content —
	// because the specific code here is net/http's behaviour, not this
	// repository's contract, and pinning 307 would fail on a stdlib change
	// that broke nothing. The measured value is recorded above so a change is
	// visible to a reader even though the test tolerates it.
	// TestHandleStaticResource_TraversalInPathValueIsRefused is the one with
	// teeth: it puts the hostile value where the handler actually reads it.
	if rr.Code/100 == 2 {
		t.Errorf("directory traversal returned %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "root:") {
		t.Errorf("passwd content reached the response: %q", rr.Body.String())
	}
}

// A directory inside the root is refused, and refused without listing it.
// http.ServeFileFS renders a directory listing when handed a directory, so
// discarding the FileInfo from root.Stat would hand an unauthenticated caller
// an index of the whole resources tree.
func TestHandleStaticResource_DirectoryIsNotListed(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "emoji"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "emoji", "secret-name.json"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := newTestServer(t)
	s.staticResourcesDir = root
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/{path...}", s.handleStaticResource)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/static/emoji", nil))

	if rr.Code != http.StatusNotFound {
		t.Errorf("a directory request: expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "secret-name.json") {
		t.Errorf("the directory listing was served: %q", rr.Body.String())
	}
}

// TestHandleStaticResource_SymlinkOutsideRootIsRefused is the regression test
// for #68, and it is the exact probe that reproduced it: before the fix this
// returned 200 with the contents of a file outside the resources root.
//
// A symlink is the case lexical containment cannot see. filepath.Abs does not
// resolve symlinks, so the old check compared a lexical path that stayed
// inside the root against reads that followed a physical one that did not.
func TestHandleStaticResource_SymlinkOutsideRootIsRefused(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("SECRET-OUTSIDE-ROOT"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	s := newTestServer(t)
	s.staticResourcesDir = root
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/{path...}", s.handleStaticResource)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/static/link.txt", nil))

	// The exact status, not merely "not 200": os.Root refuses the escape at
	// Stat, so the answer is 404. Accepting any non-200 would also accept a
	// 301, a 403 from some future guard, or a 500 — three different bugs
	// wearing the same green.
	if rr.Code != http.StatusNotFound {
		t.Errorf("a symlink out of the resources root: expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "SECRET-OUTSIDE-ROOT") {
		t.Errorf("content from outside the resources root reached the response: %q", rr.Body.String())
	}
}

// The sibling-directory class, reached the only way a request can reach it:
// a relative symlink. The old containment used strings.HasPrefix without a
// separator boundary, so "/…/res-evil/x" counted as inside "/…/res".
func TestHandleStaticResource_SymlinkToSiblingDirectoryIsRefused(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "res")
	sibling := filepath.Join(base, "res-evil")
	for _, d := range []string{root, sibling} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(sibling, "secret.txt"), []byte("SIBLING-SECRET"), 0o600); err != nil {
		t.Fatalf("write sibling file: %v", err)
	}
	if err := os.Symlink("../res-evil/secret.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	s := newTestServer(t)
	s.staticResourcesDir = root
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/{path...}", s.handleStaticResource)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/static/link.txt", nil))

	if rr.Code != http.StatusNotFound {
		t.Errorf("a symlink into a sibling directory: expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "SIBLING-SECRET") {
		t.Errorf("sibling-directory content reached the response: %q", rr.Body.String())
	}
}

// The handler's own guard, tested without the mux. ServeMux normalises the
// request path before it ever reaches PathValue, so a traversal written into
// the URL may be cleaned away by the router rather than refused by the
// handler — which makes a mux-driven test agree with a handler that has no
// guard at all. SetPathValue puts the hostile value where the handler reads
// it.
func TestHandleStaticResource_TraversalInPathValueIsRefused(t *testing.T) {
	s := newTestServer(t)
	s.staticResourcesDir = t.TempDir()

	for _, p := range []string{"../../etc/passwd", "..", "/etc/passwd", "a/../../b"} {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/static/x", nil)
			req.SetPathValue("path", p)
			rr := httptest.NewRecorder()
			s.handleStaticResource(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Errorf("path %q: expected 403, got %d: %s", p, rr.Code, rr.Body.String())
			}
		})
	}
}

// Containment must fail CLOSED when the root cannot be opened. The old code
// discarded both filepath.Abs errors, leaving absRoot empty — and
// HasPrefix(anything, "") is true, so an unresolvable root switched the check
// off instead of turning the request away.
func TestHandleStaticResource_UnopenableRootFailsClosed(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "regular-file")
	if err := os.WriteFile(notADir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	s := newTestServer(t)
	s.staticResourcesDir = notADir
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/{path...}", s.handleStaticResource)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/static/anything.txt", nil))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("an unopenable resources root: expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "not a directory") {
		t.Errorf("the root file's own contents were served: %q", rr.Body.String())
	}
}

// A file genuinely inside the root is still served — the containment fix is
// worthless if it also refuses the traffic the route exists for, and a
// negative-only test suite would not notice.
func TestHandleStaticResource_NestedFileIsStillServed(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "emoji", "v1"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "emoji", "v1", "data.json"), []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := newTestServer(t)
	s.staticResourcesDir = root
	mux := http.NewServeMux()
	mux.HandleFunc("GET /static/{path...}", s.handleStaticResource)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/static/emoji/v1/data.json", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for a file inside the root, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `{"ok":true}`) {
		t.Errorf("expected the file contents, got %q", rr.Body.String())
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

	conn, _, err := ws.Dial(ctx, wsURL, nil) //nolint:bodyclose // coder/websocket owns the handshake response; its Dial docs state you never close resp.Body yourself.
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
