package rest

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
)

// handleStaticResource serves static files from the configured resources
// directory. Used for emoji data, dictionaries, release notes, and other
// assets that Signal clients fetch from resourcesUrl/updatesUrl.
//
// Containment is enforced by os.Root, not by comparing path strings.
//
// The previous version checked lexically: reject a cleaned path containing
// "..", join it onto the root, then require the absolute result to have the
// root as a prefix. That cannot hold, and did not. It reasons about a LEXICAL
// path while os.Stat and http.ServeFile follow a PHYSICAL one — filepath.Abs
// does not resolve symlinks, only filepath.EvalSymlinks does — so a symlink
// inside the resources directory pointing outside it passed every check and
// was served in full, on a route with no authentication (#68).
//
// Two further holes in the same check, both measured: strings.HasPrefix
// without a separator boundary admits a sibling directory whose name extends
// the root's ("/…/res-evil/x" is prefixed by "/…/res"), and both
// filepath.Abs errors were discarded, leaving absRoot empty — where
// HasPrefix(anything, "") is true, so an unresolvable root disabled
// containment entirely.
//
// os.Root resolves each component against an open directory handle and refuses
// to leave it, symlinks included, so the string no longer has to carry a
// guarantee it cannot make.
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

	// fs.FS names are slash-separated, relative, and carry no "." or ".."
	// elements. Rejecting rather than normalising keeps a traversal attempt an
	// error the operator can see, instead of quietly resolving it to whatever
	// file that path happens to land on.
	//
	// This is defence in depth, not the containment: os.Root would refuse an
	// escape regardless. It exists so the refusal is a 403 that names the
	// reason rather than a 404 indistinguishable from a typo.
	name := path.Clean(reqPath)
	if name == "." || !fs.ValidPath(name) {
		writeError(w, http.StatusForbidden, "invalid path")
		return
	}

	root, err := os.OpenRoot(s.staticResourcesDir)
	if err != nil {
		// Fail CLOSED. The old code discarded the equivalent errors and, since
		// HasPrefix(x, "") is true, an unresolvable root switched containment
		// off rather than turning the request away.
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

	// Directories are refused, and with the same 404. http.ServeFileFS serves a
	// directory by rendering its listing, so discarding this FileInfo would
	// hand an unauthenticated caller an index of the resources tree — every
	// filename, on a route with no auth and no rate limit. Clients fetch named
	// assets (emoji data, dictionaries, release notes); nothing in the protocol
	// asks for a listing, and no route or config here consumes one.
	if info.IsDir() {
		writeError(w, http.StatusNotFound, "resource not found")
		return
	}

	// #nosec G703 -- the taint is real and the containment is not lexical, which
	// is the part gosec's analysis cannot see: name comes from the request, and
	// root.FS() is backed by an open directory handle that refuses to resolve
	// any component outside it, symlinks included. That is enforced, not
	// asserted — TestHandleStaticResource_SymlinkOutsideRootIsRefused and
	// TestHandleStaticResource_SymlinkToSiblingDirectoryIsRefused both still
	// pass with the lexical check above deleted entirely, which is the mutation
	// that would falsify this comment. The previous version of this handler is
	// why the annotation says that rather than "paths are validated": its
	// checks were lexical, and it served files outside the root (#68).
	http.ServeFileFS(w, r, root.FS(), name)
}
