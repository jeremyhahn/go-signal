package rest

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/audit"
)

// handleSetRegistrationLock processes PUT /v1/accounts/registration_lock and
// sets the registration lock PIN on the authenticated account.
func (s *Server) handleSetRegistrationLock(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		if s.audit != nil {
			s.audit.Denied(r.Context(), audit.ActionSetRegistrationLock, "", nil)
		}
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req RegistrationLockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode registration lock request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RegistrationLock == "" {
		writeError(w, http.StatusBadRequest, "registrationLock must not be empty")
		return
	}

	if err := s.accounts.SetRegistrationLock(r.Context(), acct.UUID, req.RegistrationLock); err != nil {
		s.logger.Error("failed to set registration lock",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		if s.audit != nil {
			s.audit.Failure(r.Context(), audit.ActionSetRegistrationLock, acct.UUID,
				map[string]any{"error": err.Error()})
		}
		writeError(w, http.StatusInternalServerError, "failed to set registration lock")
		return
	}

	if s.audit != nil {
		// Never log the PIN itself — only confirmation that it was set.
		s.audit.Success(r.Context(), audit.ActionSetRegistrationLock, acct.UUID, nil)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoveRegistrationLock processes DELETE /v1/accounts/registration_lock
// and clears the registration lock on the authenticated account.
func (s *Server) handleRemoveRegistrationLock(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	if err := s.accounts.ClearRegistrationLock(r.Context(), acct.UUID); err != nil {
		s.logger.Error("failed to clear registration lock",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to clear registration lock")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleSetPhoneNumberDiscoverability processes
// PUT /v2/accounts/phone_number_discoverability and sets whether the
// authenticated account is discoverable by phone number.
func (s *Server) handleSetPhoneNumberDiscoverability(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req PhoneNumberDiscoverabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode phone number discoverability request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.accounts.SetPhoneNumberDiscoverability(r.Context(), acct.UUID, req.DiscoverableByPhoneNumber); err != nil {
		s.logger.Error("failed to set phone number discoverability",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to set phone number discoverability")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleGetDataReport processes GET /v2/accounts/data_report and returns a
// summary of the authenticated account's data.
func (s *Server) handleGetDataReport(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	report, err := s.accounts.GetDataReport(r.Context(), acct.UUID)
	if err != nil {
		s.logger.Error("failed to get data report",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to get data report")
		return
	}

	writeJSON(w, http.StatusOK, report)
}
