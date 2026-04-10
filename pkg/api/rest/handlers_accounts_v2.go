package rest

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// handleChangeNumber processes PUT /v2/accounts/number and changes the phone
// number associated with the authenticated account. This endpoint is called by
// signal-cli's finishChangeNumber command after the new number has been verified.
func (s *Server) handleChangeNumber(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	// Only the primary device may change the phone number.
	primary := acct.PrimaryDevice()
	if primary == nil || primary.ID != accounts.PrimaryDeviceID {
		writeError(w, http.StatusForbidden, "only the primary device may change the phone number")
		return
	}

	var req ChangeNumberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode change number request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Number == "" {
		writeError(w, http.StatusUnprocessableEntity, "number must not be empty")
		return
	}

	if !isValidE164(req.Number) {
		writeError(w, http.StatusBadRequest, "invalid phone number format")
		return
	}

	// Decode PNI identity key if provided.
	var pniIdentityKey []byte
	if req.PniIdentityKey != "" {
		var err error
		pniIdentityKey, err = decodeBase64(req.PniIdentityKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid pniIdentityKey encoding")
			return
		}
	}

	updatedAcct, err := s.accounts.ChangeNumber(r.Context(), acct.UUID, req.Number, pniIdentityKey)
	if err != nil {
		s.logger.Error("failed to change phone number",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to change phone number")
		return
	}

	// Update PNI registration IDs on devices if provided.
	for deviceIDStr, regID := range req.PniRegistrationIds {
		var deviceID uint64
		for _, d := range updatedAcct.Devices {
			if deviceIDStr == "1" && d.ID == accounts.PrimaryDeviceID {
				deviceID = d.ID
				break
			}
		}
		if deviceID == 0 {
			continue
		}
		pniRegID := regID
		attrs := accounts.DeviceAttributes{
			RegistrationID: &pniRegID,
		}
		if _, err := s.accounts.SetDeviceAttributes(r.Context(), acct.UUID, deviceID, attrs); err != nil {
			s.logger.Error("failed to update PNI registration ID",
				slog.String("uuid", acct.UUID),
				slog.String("error", err.Error()))
		}
	}

	// Determine storage capability.
	storageCapable := false
	for i := range updatedAcct.Devices {
		if updatedAcct.Devices[i].Capabilities.Storage {
			storageCapable = true
			break
		}
	}

	resp := AccountIdentityResponse{
		UUID:           updatedAcct.UUID,
		Number:         updatedAcct.Number,
		PNI:            "PNI:" + updatedAcct.UUID,
		StorageCapable: storageCapable,
	}

	writeJSON(w, http.StatusOK, resp)
}
