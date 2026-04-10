package rest

import "net/http"

// handleGetStorageManifestVersion processes storage manifest requests.
// Signal-cli's SyncStorageJob calls this endpoint to check for manifest
// changes. Storage requests use their own auth credentials (from
// /v1/storage/auth), not account Basic Auth, so this handler does not
// require authentication.
//
// A 204 No Content response indicates that no new manifest is available since
// the requested version.
func (s *Server) handleGetStorageManifestVersion(w http.ResponseWriter, r *http.Request) {
	// Return 204 No Content to indicate there is no updated manifest. This
	// satisfies signal-cli's SyncStorageJob which interprets 204 as "nothing
	// new to sync".
	w.WriteHeader(http.StatusNoContent)
}
