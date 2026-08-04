package rest

import "net/http"

// handleGetConfig handles GET /v1/config. This is a legacy, unauthenticated
// endpoint that is not present in the pinned Java reference (which exposes
// only the authenticated, per-account /v2/config — see handleGetRemoteConfig).
// To avoid being a dead stub it serves the platform-neutral global feature
// flags from the same remoteconfig.Manager, evaluated without an account so
// the result is deterministic and account-independent. The response uses the
// canonical name→value map shape. When no manager is configured it returns an
// empty map.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	rendered := map[string]string{}
	if s.remoteConfig != nil {
		// Empty account UUID → only platform-neutral globals render
		// deterministically; per-account bucketed flags require /v2/config.
		rendered = s.remoteConfig.Evaluate("", r.Header.Get("User-Agent"))
	}
	writeJSON(w, http.StatusOK, RemoteConfigResponse{Config: rendered})
}
