package rest

import (
	"net/http"

	"github.com/google/uuid"
)

// handleGetPaymentsAuth handles GET /v1/payments/auth and returns stub
// payment credentials.
func (s *Server) handleGetPaymentsAuth(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"username": acct.UUID,
		"password": uuid.NewString(),
	})
}

// handleGetPaymentsConversions handles GET /v1/payments/conversions and
// returns an empty currency conversion map.
func (s *Server) handleGetPaymentsConversions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"currencies": map[string]any{},
	})
}
