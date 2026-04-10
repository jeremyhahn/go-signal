package rest

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/calling"
)

// handleGetCallingRelays handles GET /v2/calling/relays and returns the
// configured TURN relay servers.
func (s *Server) handleGetCallingRelays(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	relays, err := s.calling.GetCallingRelays(r.Context())
	if err != nil {
		s.logger.Error("failed to get calling relays", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, relays)
}

// handleGetCallLinkAuth handles POST /v1/call-link/create-auth and issues
// a call link credential using zkgroup.
func (s *Server) handleGetCallLinkAuth(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req calling.CreateCallLinkCredentialRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}
	}

	auth, err := s.calling.CreateCallLinkAuth(r.Context(), acct.UUID, req.CreateCallLinkCredentialRequest)
	if err != nil {
		s.logger.Error("failed to create call link auth", "error", err.Error())
		writeError(w, http.StatusBadRequest, "invalid credential request")
		return
	}

	writeJSON(w, http.StatusOK, auth)
}

// handleSubmitCallQualitySurvey handles PUT /v1/call_quality_survey and
// accepts a call quality survey submission. This endpoint MUST be
// unauthenticated; matching Java's behavior, authenticated requests are
// rejected with 403.
func (s *Server) handleSubmitCallQualitySurvey(w http.ResponseWriter, r *http.Request) {
	// Java: throws ForbiddenException if authenticatedDevice.isPresent()
	if acct := accountFromContext(r.Context()); acct != nil {
		writeError(w, http.StatusForbidden, "authenticated requests not allowed")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req calling.CallQualitySurveyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	remoteAddr := r.RemoteAddr
	userAgent := r.Header.Get("User-Agent")

	if err := s.calling.SubmitCallQualitySurvey(r.Context(), &req, remoteAddr, userAgent); err != nil {
		if _, ok := err.(*calling.SurveyValidationError); ok {
			writeError(w, http.StatusBadRequest, "invalid survey submission")
			return
		}
		s.logger.Error("failed to submit call quality survey", "error", err.Error())
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
