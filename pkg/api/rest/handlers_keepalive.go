package rest

import "net/http"

// handleKeepalive processes GET /v1/keepalive and returns a 200 OK health
// check response.
func (s *Server) handleKeepalive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleKeepaliveProvisioning processes GET /v1/keepalive/provisioning and
// returns a 200 OK response for the provisioning subsystem health check.
func (s *Server) handleKeepaliveProvisioning(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
