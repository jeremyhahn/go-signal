package rest

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// handleGetProvisioningCode processes GET /v1/devices/provisioning/code and
// returns a new provisioning code for the authenticated account.
func (s *Server) handleGetProvisioningCode(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	code, err := s.devices.CreateProvisioningCode(r.Context(), acct.UUID)
	if err != nil {
		s.logger.Error("failed to create provisioning code",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to create provisioning code")
		return
	}

	writeJSON(w, http.StatusOK, code)
}

// handleLinkDevice processes PUT /v1/devices/link and links a new device to
// the authenticated account using a provisioning code.
func (s *Server) handleLinkDevice(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req LinkDeviceRequestEntity
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := s.devices.LinkDevice(r.Context(), req.VerificationCode, req.toLinkDeviceRequest())
	if err != nil {
		s.logger.Error("failed to link device",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusForbidden, "failed to link device")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleSetDeviceCapabilities processes PUT /v1/devices/capabilities and
// updates the capabilities of the primary device on the authenticated account.
func (s *Server) handleSetDeviceCapabilities(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req SetDeviceCapabilitiesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.devices.SetCapabilities(r.Context(), acct.UUID, accounts.PrimaryDeviceID, req.Capabilities); err != nil {
		s.logger.Error("failed to set device capabilities",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to set capabilities")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
