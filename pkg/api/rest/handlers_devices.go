package rest

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// handleListDevices processes GET /v1/devices and returns a list of all
// devices linked to the authenticated account.
func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	devices := make([]DeviceInfoEntity, 0, len(acct.Devices))
	for _, dev := range acct.Devices {
		devices = append(devices, DeviceInfoEntity{
			ID:       dev.ID,
			Name:     dev.Name,
			Created:  dev.CreatedAt.UnixMilli(),
			LastSeen: dev.LastSeen.UnixMilli(),
		})
	}

	writeJSON(w, http.StatusOK, DeviceInfoListEntity{Devices: devices})
}

// handleRemoveDevice processes DELETE /v1/devices/{device_id} and unlinks the
// specified device from the authenticated account.
func (s *Server) handleRemoveDevice(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	deviceIDStr := r.PathValue("device_id")
	deviceID, err := strconv.ParseUint(deviceIDStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device_id")
		return
	}

	if _, err := s.accounts.RemoveDevice(r.Context(), acct.UUID, deviceID); err != nil {
		var pdrErr *accounts.PrimaryDeviceRemovalError
		if errors.As(err, &pdrErr) {
			writeError(w, http.StatusForbidden, "cannot remove primary device")
			return
		}
		var dnfErr *accounts.DeviceNotFoundError
		if errors.As(err, &dnfErr) {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}
		s.logger.Error("failed to remove device",
			slog.String("uuid", acct.UUID),
			slog.Uint64("deviceId", deviceID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to remove device")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
