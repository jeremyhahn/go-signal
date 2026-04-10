package rest

import "net/http"

// handleGetStorageAuth handles GET /v1/storage/auth and returns stub
// credentials for the secure storage service.
func (s *Server) handleGetStorageAuth(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	creds, err := s.secureStorage.GetAuth(r.Context(), acct.UUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, creds)
}
