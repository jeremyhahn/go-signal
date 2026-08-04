package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/audit"
)

// handleWhoAmI processes GET /v1/accounts/whoami and returns the authenticated
// account's identity.
func (s *Server) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeJSON(w, http.StatusOK, WhoAmIResponse{
		UUID:   acct.UUID,
		Number: acct.Number,
		PNI:    accounts.ServiceIdentifierString(accounts.IdentityTypePNI, acct.PNI),
	})
}

// handleSetAccountAttributes processes PUT /v1/accounts/attributes/ and
// updates the authenticated account's attributes.
func (s *Server) handleSetAccountAttributes(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req AccountAttributesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode account attributes", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UnidentifiedAccessKey != "" {
		uak, err := decodeBase64(req.UnidentifiedAccessKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid unidentifiedAccessKey encoding")
			return
		}
		acct.UnidentifiedAccessKey = uak
	}

	fetchesMessages := req.FetchesMessages
	caps := deviceCapabilitiesFromMap(req.Capabilities)
	attrs := accounts.DeviceAttributes{
		Name:            req.Name,
		FetchesMessages: &fetchesMessages,
		Capabilities:    &caps,
	}

	if req.RegistrationId != 0 {
		regID := req.RegistrationId
		attrs.RegistrationID = &regID
	}

	updatedAcct, err := s.accounts.SetDeviceAttributes(r.Context(), acct.UUID, deviceIDFromContext(r.Context()), attrs)
	if err != nil {
		s.logger.Error("failed to set device attributes",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to update attributes")
		return
	}

	// Apply account-level fields to the freshly-versioned account returned
	// by SetDeviceAttributes, then persist. Using the stale acct from the
	// auth middleware context would cause a version conflict.
	updatedAcct.UnidentifiedAccessKey = acct.UnidentifiedAccessKey
	if err := s.accounts.Update(r.Context(), updatedAcct); err != nil {
		s.logger.Error("failed to update account",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to update account")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleAccountExists processes HEAD /v1/accounts/account/{identifier} and
// returns 200 if the account exists, 404 otherwise. This endpoint is rate
// limited by IP to prevent enumeration. Both authenticated and unauthenticated
// requests are accepted, matching the Java Signal-Server's OptionalAccess
// pattern where the endpoint works regardless of auth state.
func (s *Server) handleAccountExists(w http.ResponseWriter, r *http.Request) {
	identifier := r.PathValue("identifier")
	// Validate the identifier shape before touching the store so an
	// arbitrary string can't be probed against the KV keyspace. Only a UUID
	// or an E.164 number is a valid account identifier here.
	if _, err := uuid.Parse(identifier); err != nil && !isValidE164(identifier) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	_, err := s.resolveAccount(r, identifier)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteAccount processes DELETE /v1/accounts/me and removes the
// authenticated account.
func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		if s.audit != nil {
			s.audit.Denied(r.Context(), audit.ActionDeleteAccount, "", nil)
		}
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	if err := s.accounts.Delete(r.Context(), acct.UUID); err != nil {
		s.logger.Error("failed to delete account",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		if s.audit != nil {
			s.audit.Failure(r.Context(), audit.ActionDeleteAccount, acct.UUID,
				map[string]any{"error": err.Error()})
		}
		writeError(w, http.StatusInternalServerError, "failed to delete account")
		return
	}

	if s.audit != nil {
		s.audit.Success(r.Context(), audit.ActionDeleteAccount, acct.UUID, nil)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRegisterGcm processes PUT /v1/accounts/gcm/ and stores the GCM
// registration token for the authenticated account's primary device.
func (s *Server) handleRegisterGcm(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req GcmRegistrationIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode GCM request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	attrs := accounts.DeviceAttributes{
		GcmRegistrationID: req.GcmRegistrationID,
	}

	if _, err := s.accounts.SetDeviceAttributes(r.Context(), acct.UUID, deviceIDFromContext(r.Context()), attrs); err != nil {
		s.logger.Error("failed to register GCM",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to register GCM")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleUnregisterGcm processes DELETE /v1/accounts/gcm/ and clears the GCM
// registration token for the authenticated account's primary device.
func (s *Server) handleUnregisterGcm(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	deviceID := deviceIDFromContext(r.Context())
	if acct.GetDevice(deviceID) == nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	if _, err := s.accounts.ClearGcmRegistration(r.Context(), acct.UUID, deviceID); err != nil {
		var notFound *accounts.DeviceNotFoundError
		if errors.As(err, &notFound) {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}
		s.logger.Error("failed to unregister GCM",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to unregister GCM")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleRegisterApn processes PUT /v1/accounts/apn/ and stores the APN
// registration token for the authenticated account's primary device.
func (s *Server) handleRegisterApn(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req ApnRegistrationIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode APN request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	attrs := accounts.DeviceAttributes{
		ApnRegistrationID:     req.ApnRegistrationID,
		VoipApnRegistrationID: req.VoipRegistrationID,
	}

	if _, err := s.accounts.SetDeviceAttributes(r.Context(), acct.UUID, deviceIDFromContext(r.Context()), attrs); err != nil {
		s.logger.Error("failed to register APN",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to register APN")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleUnregisterApn processes DELETE /v1/accounts/apn/ and clears the APN
// registration token for the authenticated account's primary device.
func (s *Server) handleUnregisterApn(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	deviceID := deviceIDFromContext(r.Context())
	if acct.GetDevice(deviceID) == nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	if _, err := s.accounts.ClearApnRegistration(r.Context(), acct.UUID, deviceID); err != nil {
		var notFound *accounts.DeviceNotFoundError
		if errors.As(err, &notFound) {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}
		s.logger.Error("failed to unregister APN",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to unregister APN")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
