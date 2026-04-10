package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// testFrontendFS builds a minimal in-memory FS that mimics a Vite build output:
// index.html at the root and a hashed JS bundle under assets/.
func testFrontendFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html": {
			Data: []byte(`<!DOCTYPE html><html><body>app</body></html>`),
		},
		"assets/app-abc123.js": {
			Data: []byte(`console.log("hello");`),
		},
		"assets/style-def456.css": {
			Data: []byte(`body{margin:0}`),
		},
		"favicon.ico": {
			Data: []byte(`ico`),
		},
	}
}

func TestFrontendHandler_ServeIndex(t *testing.T) {
	h := newFrontendHandler(testFrontendFS())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-cache, no-store, must-revalidate" {
		t.Errorf("unexpected Cache-Control for /: %q", got)
	}
	if rr.Body.Len() == 0 {
		t.Error("expected non-empty body for index.html")
	}
}

func TestFrontendHandler_ServeIndexHTML_Redirects(t *testing.T) {
	h := newFrontendHandler(testFrontendFS())

	// http.FileServer canonicalises /index.html → / with a 301 redirect.
	// This is the expected behaviour; clients following the redirect land on /
	// which is served with no-cache headers.
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMovedPermanently {
		t.Errorf("expected 301 redirect for /index.html, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "./" {
		t.Errorf("unexpected Location header: %q", loc)
	}
}

func TestFrontendHandler_ServeAsset_Immutable(t *testing.T) {
	h := newFrontendHandler(testFrontendFS())

	req := httptest.NewRequest(http.MethodGet, "/assets/app-abc123.js", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("unexpected Cache-Control for hashed asset: %q", got)
	}
}

func TestFrontendHandler_ServeOtherStaticFile(t *testing.T) {
	h := newFrontendHandler(testFrontendFS())

	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("unexpected Cache-Control for favicon.ico: %q", got)
	}
}

func TestFrontendHandler_SPAFallback_UnknownPath(t *testing.T) {
	h := newFrontendHandler(testFrontendFS())

	// A client-side route that has no matching file should get index.html.
	req := httptest.NewRequest(http.MethodGet, "/conversations/abc123", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 SPA fallback, got %d", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-cache, no-store, must-revalidate" {
		t.Errorf("SPA fallback should set no-cache: %q", got)
	}
}

func TestFrontendHandler_SPAFallback_NestedRoute(t *testing.T) {
	h := newFrontendHandler(testFrontendFS())

	req := httptest.NewRequest(http.MethodGet, "/settings/privacy/blocked", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 SPA fallback for nested route, got %d", rr.Code)
	}
}

func TestFrontendHandler_MethodNotAllowed(t *testing.T) {
	h := newFrontendHandler(testFrontendFS())

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s /: expected 405, got %d", method, rr.Code)
			}
			if allow := rr.Header().Get("Allow"); allow != "GET, HEAD" {
				t.Errorf("Allow header: expected %q, got %q", "GET, HEAD", allow)
			}
		})
	}
}

func TestFrontendHandler_HeadRequest(t *testing.T) {
	h := newFrontendHandler(testFrontendFS())

	req := httptest.NewRequest(http.MethodHead, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("HEAD /: expected 200, got %d", rr.Code)
	}
}

func TestFrontendHandler_CSSAsset_Immutable(t *testing.T) {
	h := newFrontendHandler(testFrontendFS())

	req := httptest.NewRequest(http.MethodGet, "/assets/style-def456.css", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("unexpected Cache-Control for hashed CSS asset: %q", got)
	}
}

func TestNewServer_FrontendHandlerRegistered(t *testing.T) {
	s := newTestServer(t)
	s.frontendFS = testFrontendFS()
	// Re-register routes on a fresh mux to pick up the new frontendFS.
	mux := http.NewServeMux()
	s.mux = mux
	s.routes(mux)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 from SPA handler at /, got %d", rr.Code)
	}
}

func TestNewServer_FrontendDisabled_404(t *testing.T) {
	s := newTestServer(t)
	// frontendFS is nil by default in newTestServer; / should 404.
	req := httptest.NewRequest(http.MethodGet, "/not-an-api-route", nil)
	rr := httptest.NewRecorder()
	s.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 when frontend is disabled, got %d", rr.Code)
	}
}

func TestFrontendHandler_PathWithoutLeadingSlash(t *testing.T) {
	h := newFrontendHandler(testFrontendFS())

	// Craft a request where the URL path lacks a leading slash. The handler
	// normalises it before probing the embedded FS.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.URL.Path = "favicon.ico" // strip the leading slash
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// Should resolve to the real file and return 200.
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestNewServer_APIRoutesTakePriorityOverFrontend(t *testing.T) {
	s := newTestServer(t)
	s.frontendFS = testFrontendFS()
	mux := http.NewServeMux()
	s.mux = mux
	s.routes(mux)

	// /v1/accounts/whoami is a real API route; it should not be handled by
	// the SPA catch-all (it will return 401 without credentials, not 200).
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/whoami", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Error("API route /v1/accounts/whoami should not be served by the SPA handler")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 from API route, got %d", rr.Code)
	}
}
