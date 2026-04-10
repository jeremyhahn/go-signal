package rest

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleStaticResource serves static files from the configured resources
// directory. Used for emoji data, dictionaries, release notes, and other
// assets that Signal clients fetch from resourcesUrl/updatesUrl.
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

	// Security: prevent directory traversal.
	cleaned := filepath.Clean(reqPath)
	if strings.Contains(cleaned, "..") {
		writeError(w, http.StatusForbidden, "invalid path")
		return
	}

	filePath := filepath.Join(s.staticResourcesDir, cleaned)

	// Ensure the resolved path is within the resources directory.
	absRoot, _ := filepath.Abs(s.staticResourcesDir)
	absFile, _ := filepath.Abs(filePath)
	if !strings.HasPrefix(absFile, absRoot) {
		writeError(w, http.StatusForbidden, "path outside resources directory")
		return
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "resource not found")
		return
	}

	http.ServeFile(w, r, filePath)
}
