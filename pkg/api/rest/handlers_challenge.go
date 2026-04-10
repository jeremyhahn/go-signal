package rest

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/captcha"
)

// handleChallengeResponse processes PUT /v1/challenge and verifies a
// challenge response submitted by an authenticated client. Supports both
// CAPTCHA and push-based rate limit challenges.
func (s *Server) handleChallengeResponse(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var resp captcha.ChallengeResponse
	if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
		s.logger.Error("failed to decode challenge response",
			slog.String("error", err.Error()),
		)
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.captcha.HandleChallengeResponse(r.Context(), acct.UUID, &resp); err != nil {
		s.logger.Error("challenge verification failed",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()),
		)
		writeError(w, http.StatusForbidden, "challenge verification failed")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleRequestPushChallenge processes POST /v1/challenge/push and issues a
// new push-based rate limit challenge to the authenticated client.
func (s *Server) handleRequestPushChallenge(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	_, err := s.captcha.SendPushChallenge(r.Context(), acct.UUID)
	if err != nil {
		s.logger.Error("failed to send push challenge",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()),
		)
		writeError(w, http.StatusInternalServerError, "failed to send push challenge")
		return
	}

	w.WriteHeader(http.StatusOK)
}
