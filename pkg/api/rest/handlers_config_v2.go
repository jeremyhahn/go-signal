package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// defaultRemoteConfig defines the global remote configuration items returned
// to authenticated clients. Each entry maps directly to a RemoteConfigItem.
var defaultRemoteConfig = []RemoteConfigItem{
	{Name: "global.calling", Enabled: true, Value: "TRUE"},
	{Name: "global.groupsv2", Enabled: true, Value: "TRUE"},
	{Name: "global.storage", Enabled: true, Value: "TRUE"},
	{Name: "global.senderKey", Enabled: true, Value: "TRUE"},
	{Name: "global.stories", Enabled: true, Value: "TRUE"},
	{Name: "global.giftBadges", Enabled: true, Value: "TRUE"},
}

// configETag is a precomputed hash of the default config for caching.
var configETag string

func init() {
	data, _ := json.Marshal(defaultRemoteConfig)
	// Use a stable 16-hex-char ETag derived from the config contents.
	var h uint64
	for _, b := range data {
		h = h*31 + uint64(b)
	}
	configETag = fmt.Sprintf("%016x", h)
}

// handleGetRemoteConfig processes GET /v2/config and returns the remote
// configuration as a structured list of RemoteConfigItem entries. Requires
// authentication via authMiddleware. Includes required x-signal-timestamp
// and ETag headers for conditional request support.
func (s *Server) handleGetRemoteConfig(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Support conditional requests via If-None-Match.
	if r.Header.Get("If-None-Match") == configETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("X-Signal-Timestamp", fmt.Sprintf("%d", time.Now().UnixMilli()))
	w.Header().Set("ETag", configETag)

	writeJSON(w, http.StatusOK, RemoteConfigResponse{
		Config: defaultRemoteConfig,
	})
}
