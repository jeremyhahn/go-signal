package rest

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// handleCreateVerificationSession processes POST /v1/verification/session.
//
// Security invariants:
//   - This endpoint is unauthenticated; session management is enforced by the
//     verification.Manager service layer.
//   - Session count is capped at MaxSessions (default 10,000) by the Manager;
//     exceeding the cap returns HTTP 429 (Too Many Requests).
//   - Each session is assigned a TTL of SessionTTL (default 10 minutes); the
//     Manager's background cleanup goroutine evicts expired sessions every
//     CleanupInterval (default 60 seconds).
func (s *Server) handleCreateVerificationSession(w http.ResponseWriter, r *http.Request) {
	var req CreateVerificationSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Number == "" {
		writeError(w, http.StatusBadRequest, "number is required")
		return
	}

	if s.verification == nil {
		writeError(w, http.StatusServiceUnavailable, "verification service unavailable")
		return
	}

	session, err := s.verification.CreateSession(r.Context(), req.Number)
	if err != nil {
		var limitExceeded *verification.SessionLimitExceededError
		if errors.As(err, &limitExceeded) {
			writeError(w, http.StatusTooManyRequests, "too many verification sessions")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, VerificationSessionResponse{
		ID:                   session.ID,
		AllowedToRequestCode: session.AllowedToRequestCode,
		Verified:             session.Verified,
		RequestedInformation: []string{},
	})
}

// handleGetVerificationSession processes GET /v1/verification/session/{id}.
func (s *Server) handleGetVerificationSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if s.verification == nil {
		writeError(w, http.StatusServiceUnavailable, "verification service unavailable")
		return
	}

	session, err := s.verification.GetSession(r.Context(), id)
	if err != nil {
		var notFound *verification.SessionNotFoundError
		if errors.As(err, &notFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, VerificationSessionResponse{
		ID:                   session.ID,
		AllowedToRequestCode: session.AllowedToRequestCode,
		Verified:             session.Verified,
		RequestedInformation: []string{},
	})
}

// handleRequestVerificationCode processes POST /v1/verification/session/{id}/code.
func (s *Server) handleRequestVerificationCode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if s.verification == nil {
		writeError(w, http.StatusServiceUnavailable, "verification service unavailable")
		return
	}

	session, err := s.verification.SendCode(r.Context(), id)
	if err != nil {
		var notFound *verification.SessionNotFoundError
		var expired *verification.SessionExpiredError
		if errors.As(err, &notFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		if errors.As(err, &expired) {
			writeError(w, http.StatusGone, "session expired")
			return
		}
		// Transport errors and other failures return 500.
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, VerificationSessionResponse{
		ID:                   session.ID,
		AllowedToRequestCode: session.AllowedToRequestCode,
		Verified:             session.Verified,
		RequestedInformation: []string{},
	})
}

// handleSubmitVerificationCode processes PUT /v1/verification/session/{id}/code.
// It validates the submitted code via the verification.Manager using a
// constant-time comparison to prevent timing attacks. The session must exist
// and the code must match exactly; expired sessions and invalid codes each
// return distinct 4xx status codes.
func (s *Server) handleSubmitVerificationCode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req SubmitVerificationCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}

	if s.verification == nil {
		writeError(w, http.StatusServiceUnavailable, "verification service unavailable")
		return
	}

	session, err := s.verification.SubmitCode(r.Context(), id, req.Code)
	if err != nil {
		var notFound *verification.SessionNotFoundError
		var expired *verification.SessionExpiredError
		var codeExpired *verification.CodeExpiredError
		var maxAttempts *verification.MaxAttemptsExceededError
		var invalidCode *verification.InvalidCodeError

		switch {
		case errors.As(err, &notFound):
			writeError(w, http.StatusNotFound, "session not found")
		case errors.As(err, &expired):
			writeError(w, http.StatusGone, "session expired")
		case errors.As(err, &codeExpired):
			writeError(w, http.StatusGone, "code expired")
		case errors.As(err, &maxAttempts):
			writeError(w, http.StatusTooManyRequests, "max attempts exceeded")
		case errors.As(err, &invalidCode):
			writeError(w, http.StatusForbidden, "invalid code")
		default:
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	writeJSON(w, http.StatusOK, VerificationSessionResponse{
		ID:                   session.ID,
		AllowedToRequestCode: session.AllowedToRequestCode,
		Verified:             session.Verified,
		RequestedInformation: []string{},
	})
}
