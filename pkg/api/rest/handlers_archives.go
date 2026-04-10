package rest

import "net/http"

// handleGetBackupAuth handles GET /v1/archives/auth. Backup credential
// issuance is not yet implemented; returns 501.
func (s *Server) handleGetBackupAuth(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeError(w, http.StatusNotImplemented, "not implemented")
}

// handleGetBackupInfo handles GET /v1/archives. Backup information
// retrieval is not yet implemented; returns 501.
func (s *Server) handleGetBackupInfo(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeError(w, http.StatusNotImplemented, "not implemented")
}

// handleSetBackupId handles PUT /v1/archives/backupid. Backup ID management
// is not yet implemented; returns 501.
func (s *Server) handleSetBackupId(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeError(w, http.StatusNotImplemented, "not implemented")
}

// handleGetBackupUploadForm handles GET /v1/archives/upload/form. Backup
// upload form generation is not yet implemented; returns 501.
func (s *Server) handleGetBackupUploadForm(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeError(w, http.StatusNotImplemented, "not implemented")
}

// handleRefreshBackup handles POST /v1/archives. Backup refresh is not yet
// implemented; returns 501.
func (s *Server) handleRefreshBackup(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeError(w, http.StatusNotImplemented, "not implemented")
}
