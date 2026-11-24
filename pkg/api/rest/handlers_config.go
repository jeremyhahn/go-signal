package rest

import "net/http"

// handleGetConfig serves GET /v1/config: the global feature flags from remoteconfig.Manager, evaluated without an account, or an empty map.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	rendered := map[string]string{}
	if s.remoteConfig != nil {
		// Empty account UUID → only platform-neutral globals render
		// deterministically; per-account bucketed flags require /v2/config.
		rendered = s.remoteConfig.Evaluate("", r.Header.Get("User-Agent"))
	}
	writeJSON(w, http.StatusOK, RemoteConfigResponse{Config: rendered})
}
