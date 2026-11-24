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

// handleGetRemoteConfig handles GET /v2/config, returning the account's dynamic config with an ETag for If-None-Match.
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

// remoteConfigETag hashes the config as sorted JSON, independent of map order.
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
