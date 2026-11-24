package rest

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
)

// handleStaticResource serves files from the resources directory; os.Root enforces containment, symlinks included.
func (s *Server) handleStaticResource(w http.ResponseWriter, r *http.Request) {
	if s.staticResourcesDir == "" {
		writeError(w, http.StatusNotFound, "static resources not configured")
		return
	}

	reqPath := r.PathValue("path")
	if reqPath == "" {
		writeError(w, http.StatusBadRequest, "missing path")
		return
	}

	// Reject non-canonical fs.FS names with a 403, as defence in depth.
	name := path.Clean(reqPath)
	if name == "." || !fs.ValidPath(name) {
		writeError(w, http.StatusForbidden, "invalid path")
		return
	}

	root, err := os.OpenRoot(s.staticResourcesDir)
	if err != nil {
		// Fail closed when the root cannot be opened.
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "resource not found")
			return
		}
		s.logger.Error("static resources root could not be opened",
			slog.String("dir", s.staticResourcesDir), slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	defer func() { _ = root.Close() }()

	// An escape and a missing file are both "not found" to the caller.
	// Separating them would answer whether a path exists outside the root,
	// which is the question the escape was asking.
	info, err := root.Stat(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "resource not found")
		return
	}

	// Refuse directories with 404: ServeFileFS would render a listing.
	if info.IsDir() {
		writeError(w, http.StatusNotFound, "resource not found")
		return
	}

	// #nosec G703 -- name is request-derived, but root.FS() cannot resolve outside the root (symlink tests prove it).
	http.ServeFileFS(w, r, root.FS(), name)
}
