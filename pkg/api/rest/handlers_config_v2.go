package rest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"
)

// handleGetRemoteConfig processes GET /v2/config and returns the
// per-account dynamic configuration as a name→value map. Requires
// authentication. The ETag header is derived from the rendered
// configuration so clients can short-circuit unchanged responses via
// If-None-Match.
//
// Mirrors Java RemoteConfigController.getAll.
func (s *Server) handleGetRemoteConfig(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	rendered := map[string]string{}
	if s.remoteConfig != nil {
		rendered = s.remoteConfig.Evaluate(acct.UUID, r.Header.Get("User-Agent"))
	}
	etag := remoteConfigETag(rendered)

	// Support conditional requests via If-None-Match.
	if r.Header.Get("If-None-Match") == etag {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("X-Signal-Timestamp", fmt.Sprintf("%d", time.Now().UnixMilli()))
	w.Header().Set("ETag", etag)

	writeJSON(w, http.StatusOK, RemoteConfigResponse{Config: rendered})
}

// remoteConfigETag computes a stable hash of the rendered config map.
// Encoding is sorted JSON so the hash is invariant under map-iteration
// order — Go's ranged iteration is non-deterministic and would
// otherwise change the ETag between calls with identical content.
func remoteConfigETag(rendered map[string]string) string {
	keys := make([]string, 0, len(rendered))
	for k := range rendered {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type pair struct {
		K string `json:"k"`
		V string `json:"v"`
	}
	pairs := make([]pair, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, pair{K: k, V: rendered[k]})
	}
	canonical, _ := json.Marshal(pairs)
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:8])
}
