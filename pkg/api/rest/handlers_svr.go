package rest

import (
	"encoding/json"
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/securevaluerecovery"
)

// handleGetSVRBackupAuth handles GET /v2/backup/auth and returns stub SVR
// credentials for the "backup" service name.
func (s *Server) handleGetSVRBackupAuth(w http.ResponseWriter, r *http.Request) {
	s.handleGetSVRAuth(w, r, "backup")
}

// handleGetSVRSVRAuth handles GET /v2/svr/auth and returns stub SVR
// credentials for the "svr" service name.
func (s *Server) handleGetSVRSVRAuth(w http.ResponseWriter, r *http.Request) {
	s.handleGetSVRAuth(w, r, "svr")
}

// handleGetSVRAuth is the shared implementation for SVR auth credential
// retrieval.
func (s *Server) handleGetSVRAuth(w http.ResponseWriter, r *http.Request, name string) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	creds, err := s.svr.GetAuth(r.Context(), acct.UUID, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Written to the response, then wiped — its protected copy does not
	// outlive the request.
	defer creds.Destroy()
	writeJSONContext(r.Context(), w, http.StatusOK, *creds)
}

// handleCheckSVRBackupAuth handles POST /v2/backup/auth/check and validates
// passwords against the "backup" SVR service.
func (s *Server) handleCheckSVRBackupAuth(w http.ResponseWriter, r *http.Request) {
	s.handleCheckSVRAuth(w, r, "backup")
}

// handleCheckSVRSVRAuth handles POST /v2/svr/auth/check and validates
// passwords against the "svr" SVR service.
func (s *Server) handleCheckSVRSVRAuth(w http.ResponseWriter, r *http.Request) {
	s.handleCheckSVRAuth(w, r, "svr")
}

// handleCheckSVRAuth is the shared implementation for SVR auth checking.
func (s *Server) handleCheckSVRAuth(w http.ResponseWriter, r *http.Request, name string) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req securevaluerecovery.AuthCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := s.svr.CheckAuth(r.Context(), acct.UUID, name, req.Passwords)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}
