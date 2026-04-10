package rest

import (
	"io/fs"
	"net/http"
	"strings"
)

// frontendHandler serves the embedded React SPA. It delegates to an
// http.FileServer for requests that correspond to real files, and falls back
// to serving index.html for all other GET requests so that client-side routing
// works correctly.
//
// Cache policy follows the Vite content-hash convention:
//   - Files under /assets/ carry a content hash in the name and are served
//     with Cache-Control: public, max-age=31536000, immutable.
//   - index.html is served with Cache-Control: no-cache, no-store, must-revalidate
//     so that browsers always revalidate and pick up new deployments.
//   - All other static files receive Cache-Control: public, max-age=3600.
type frontendHandler struct {
	fileServer http.Handler
	files      fs.FS
}

// newFrontendHandler constructs a frontendHandler from the given fs.FS, which
// must be the root of the compiled Vite output (containing index.html and an
// assets/ directory).
func newFrontendHandler(files fs.FS) *frontendHandler {
	return &frontendHandler{
		fileServer: http.FileServer(http.FS(files)),
		files:      files,
	}
}

// ServeHTTP implements http.Handler. Non-GET/HEAD requests are rejected with
// 405 Method Not Allowed. Requests for paths that begin with an API prefix
// should never reach this handler (API routes are registered first and take
// priority), but as a safety net they are passed to the file server which will
// return 404.
func (h *frontendHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
	}

	// Determine whether the request maps to a real file in the embedded FS.
	// Strip the leading "/" before probing the FS because fs.FS paths do not
	// start with a slash.
	fsPath := strings.TrimPrefix(upath, "/")
	if fsPath == "" {
		fsPath = "index.html"
	}

	_, err := fs.Stat(h.files, fsPath)
	if err != nil {
		// Path not found in the FS — serve index.html for SPA client routing.
		h.serveIndex(w, r)
		return
	}

	h.setCacheHeaders(w, upath)
	h.fileServer.ServeHTTP(w, r)
}

// serveIndex serves index.html with no-cache headers so that browsers always
// revalidate and receive updated asset references after a deployment.
func (h *frontendHandler) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	// Rewrite the URL to / so the file server resolves index.html.
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/"
	h.fileServer.ServeHTTP(w, r2)
}

// setCacheHeaders sets appropriate Cache-Control headers based on the request
// path before delegating to the file server.
func (h *frontendHandler) setCacheHeaders(w http.ResponseWriter, upath string) {
	switch {
	case strings.HasPrefix(upath, "/assets/"):
		// Vite emits content-hashed filenames under /assets/; treat as
		// immutable for one year.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	case upath == "/" || strings.HasSuffix(upath, "/index.html"):
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
	default:
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
}
