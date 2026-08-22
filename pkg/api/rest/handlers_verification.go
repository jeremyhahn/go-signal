package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// verificationSessionResponse formats a session for the REST surface and
// populates requestedInformation from the session state — currently just
// the "captcha" hint when CaptchaRequired is set. Mirrors Java's
// RegistrationServiceSession.getRequestedInformation().
func verificationSessionResponse(s *verification.VerificationSession) VerificationSessionResponse {
	info := []string{}
	if s.CaptchaRequired {
		info = append(info, "captcha")
	}
	return VerificationSessionResponse{
		ID:                   s.ID,
		AllowedToRequestCode: s.AllowedToRequestCode,
		Verified:             s.Verified,
		RequestedInformation: info,
	}
}

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

	writeJSON(w, http.StatusOK, verificationSessionResponse(session))
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

	writeJSON(w, http.StatusOK, verificationSessionResponse(session))
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
		var alreadyVerified *verification.SessionAlreadyVerifiedError
		var rateLimited *verification.RequestCodeRateLimitedError
		var captchaRequired *verification.CaptchaRequiredError
		if errors.As(err, &notFound) {
			writeError(w, http.StatusNotFound, "session not found")
			return
		}
		if errors.As(err, &expired) {
			writeError(w, http.StatusGone, "session expired")
			return
		}
		if errors.As(err, &alreadyVerified) {
			// Java parity: 409 plus the session JSON, so the client sees
			// verified=true and proceeds straight to registration instead
			// of waiting out a cooldown.
			s.writeSessionConflict(w, r, id)
			return
		}
		if errors.As(err, &captchaRequired) {
			// Java parity: 409 + the session JSON so the client reads
			// requestedInformation=["captcha"] and prompts the user.
			s.writeSessionConflict(w, r, id)
			return
		}
		if errors.As(err, &rateLimited) {
			// Java's SMS rate-limit response surfaces `Retry-After` in
			// seconds so clients can honor `next_sms_seconds`.
			retrySecs := int(rateLimited.RetryAfter.Seconds())
			if retrySecs < 1 {
				retrySecs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(retrySecs))
			writeError(w, http.StatusTooManyRequests, "code request rate limited")
			return
		}
		// Transport errors and other failures return 500.
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, verificationSessionResponse(session))
}

// writeSessionConflict answers a 409 carrying the session, which is the shape
// Java uses for both the already-verified and captcha-required outcomes: the
// client reads the session state and decides what to do next.
//
// A failed reload is NOT a conflict. Reporting a storage or transport failure
// as a well-formed 409 tells the client something definite about a session
// nobody could read, and the client then acts on it — so anything other than
// a recognised session state becomes a 500. Not-found and expired are mapped
// deliberately, because those are real answers about the session rather than
// failures to obtain one.
func (s *Server) writeSessionConflict(w http.ResponseWriter, r *http.Request, id string) {
	updated, err := s.verification.GetSession(r.Context(), id)
	if err != nil {
		var notFound *verification.SessionNotFoundError
		var expired *verification.SessionExpiredError
		switch {
		case errors.As(err, &notFound):
			writeError(w, http.StatusNotFound, "session not found")
		case errors.As(err, &expired):
			writeError(w, http.StatusGone, "session expired")
		default:
			// The session id is deliberately NOT logged. A verified session
			// id is the bearer credential POST /v1/registration accepts as
			// proof of verification (enforceVerifiedSession), so writing it
			// to logs turns log access into account takeover for any number
			// with a live session.
			s.logger.Error("failed to reload verification session for conflict response",
				slog.String("error", err.Error()))
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusConflict, verificationSessionResponse(updated))
}

// handleUpdateVerificationSession processes PATCH /v1/verification/session/{id}.
// Today it accepts an optional captcha solution (provider.sitekey.action.token
// format). On success the session's CaptchaRequired flag is cleared and the
// updated session is returned. Mirrors Java RegistrationController#updateSession.
func (s *Server) handleUpdateVerificationSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if s.verification == nil {
		writeError(w, http.StatusServiceUnavailable, "verification service unavailable")
		return
	}

	var req UpdateVerificationSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// PATCH with no captcha is a no-op that simply re-reads the session.
	// Mirrors Java when the request body has no actionable fields.
	if req.Captcha == "" {
		session, err := s.verification.GetSession(r.Context(), id)
		if err != nil {
			var notFound *verification.SessionNotFoundError
			var expired *verification.SessionExpiredError
			switch {
			case errors.As(err, &notFound):
				writeError(w, http.StatusNotFound, "session not found")
			case errors.As(err, &expired):
				writeError(w, http.StatusGone, "session expired")
			default:
				writeError(w, http.StatusInternalServerError, "internal error")
			}
			return
		}
		writeJSON(w, http.StatusOK, verificationSessionResponse(session))
		return
	}

	session, err := s.verification.SubmitCaptcha(r.Context(), id, req.Captcha, ipKey(r, nil))
	if err != nil {
		var notFound *verification.SessionNotFoundError
		var expired *verification.SessionExpiredError
		var unavail *verification.CaptchaCheckUnavailableError
		var rejected *verification.CaptchaRejectedError
		switch {
		case errors.As(err, &notFound):
			writeError(w, http.StatusNotFound, "session not found")
		case errors.As(err, &expired):
			writeError(w, http.StatusGone, "session expired")
		case errors.As(err, &unavail):
			writeError(w, http.StatusServiceUnavailable, "captcha not available")
		case errors.As(err, &rejected):
			// Java parity: 422 distinguishes "the captcha didn't verify"
			// from "we couldn't reach the provider".
			writeError(w, http.StatusUnprocessableEntity, "captcha rejected")
		default:
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, verificationSessionResponse(session))
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

	writeJSON(w, http.StatusOK, verificationSessionResponse(session))
}
