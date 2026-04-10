package rest

import "net/http"

// handleGetConfig handles GET /v1/config and returns the remote configuration.
// For now this returns an empty config list.
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"config": []any{}})
}
