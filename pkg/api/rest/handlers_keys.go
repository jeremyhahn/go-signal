package rest

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// handleGetPreKeyCount processes GET /v2/keys and returns the count of
// remaining one-time pre-keys for the authenticated user's primary device.
func (s *Server) handleGetPreKeyCount(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	state, err := s.keys.GetPreKeyCount(r.Context(), acct.UUID, accounts.PrimaryDeviceID)
	if err != nil {
		s.logger.Error("failed to get pre-key count",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to get pre-key count")
		return
	}

	resp := PreKeyCountResponse{
		Count:         state.ECCount,
		PqCount:       state.KEMCount,
		HasLastResort: state.HasLastResort,
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleUploadKeys processes PUT /v2/keys and stores uploaded pre-keys for the
// authenticated user's primary device.
func (s *Server) handleUploadKeys(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req SetKeysRequestEntity
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode upload keys request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	setReq, err := convertSetKeysRequest(&req)
	if err != nil {
		s.logger.Error("failed to convert keys request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid key format")
		return
	}

	// Validate signatures on all uploaded signed and KEM pre-keys against the
	// account's identity key. This mirrors the Java isEverySignedKeyValid check.
	var signedSlice []*keys.SignedPreKey
	if setReq.SignedPreKey != nil {
		signedSlice = []*keys.SignedPreKey{setReq.SignedPreKey}
	}
	if err := keys.ValidateAllSignedKeys(acct.IdentityKey, signedSlice, setReq.KEMPreKeys); err != nil {
		s.logger.Warn("invalid pre-key signature on key upload",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusUnprocessableEntity, "invalid pre-key signature")
		return
	}

	if err := s.keys.StoreKeys(r.Context(), acct.UUID, accounts.PrimaryDeviceID, setReq); err != nil {
		s.logger.Error("failed to store keys",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to store keys")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleGetPreKeys processes GET /v2/keys/{identifier}/{device_id} and returns
// the pre-key bundle for the target account and device. The special device_id
// "*" returns bundles for all devices.
func (s *Server) handleGetPreKeys(w http.ResponseWriter, r *http.Request) {
	identifier := r.PathValue("identifier")
	deviceIDStr := r.PathValue("device_id")

	if identifier == "" {
		writeError(w, http.StatusBadRequest, "missing identifier")
		return
	}

	// The identifier must be either a well-formed UUID (account lookup by ACI)
	// or a valid E.164 phone number (account lookup by number). Any other value
	// is rejected to prevent path-traversal or injection via the identifier.
	if _, err := uuid.Parse(identifier); err != nil && !isValidE164(identifier) {
		writeError(w, http.StatusBadRequest, "invalid identifier")
		return
	}

	targetAcct, err := s.resolveAccount(r, identifier)
	if err != nil {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}

	resp := PreKeyResponseEntity{
		IdentityKey: base64.StdEncoding.EncodeToString(targetAcct.IdentityKey),
	}

	if deviceIDStr == "*" {
		// Return pre-keys for all devices.
		for _, dev := range targetAcct.Devices {
			item, err := s.getPreKeyResponseItem(r, targetAcct.UUID, &dev)
			if err != nil {
				s.logger.Error("failed to get pre-keys for device",
					slog.String("uuid", targetAcct.UUID),
					slog.Uint64("deviceId", dev.ID),
					slog.String("error", err.Error()))
				continue
			}
			resp.Devices = append(resp.Devices, *item)
		}
	} else {
		deviceID, err := strconv.ParseUint(deviceIDStr, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid device_id")
			return
		}

		dev := targetAcct.GetDevice(deviceID)
		if dev == nil {
			writeError(w, http.StatusNotFound, "device not found")
			return
		}

		item, err := s.getPreKeyResponseItem(r, targetAcct.UUID, dev)
		if err != nil {
			s.logger.Error("failed to get pre-keys",
				slog.String("uuid", targetAcct.UUID),
				slog.Uint64("deviceId", deviceID),
				slog.String("error", err.Error()))
			writeError(w, http.StatusNotFound, "pre-keys not available")
			return
		}
		resp.Devices = append(resp.Devices, *item)
	}

	if len(resp.Devices) == 0 {
		writeError(w, http.StatusNotFound, "no pre-keys available")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// getPreKeyResponseItem retrieves the pre-key bundle for a single device and
// converts it to an API response entity.
func (s *Server) getPreKeyResponseItem(r *http.Request, uuid string, dev *accounts.Device) (*PreKeyResponseItemEntity, error) {
	item, err := s.keys.GetPreKeys(r.Context(), uuid, dev.ID)
	if err != nil {
		return nil, err
	}

	entity := &PreKeyResponseItemEntity{
		DeviceId:       dev.ID,
		RegistrationId: dev.RegistrationID,
	}

	if item.SignedPreKey != nil {
		entity.SignedPreKey = &SignedPreKeyEntity{
			KeyId:     item.SignedPreKey.KeyID,
			PublicKey: base64.StdEncoding.EncodeToString(item.SignedPreKey.PublicKey),
			Signature: base64.StdEncoding.EncodeToString(item.SignedPreKey.Signature),
		}
	}

	if item.PreKey != nil {
		entity.PreKey = &PreKeyEntity{
			KeyId:     item.PreKey.KeyID,
			PublicKey: base64.StdEncoding.EncodeToString(item.PreKey.PublicKey),
		}
	}

	if item.KEMPreKey != nil {
		entity.PqPreKey = &KEMSignedPreKeyEntity{
			KeyId:     item.KEMPreKey.KeyID,
			PublicKey: base64.StdEncoding.EncodeToString(item.KEMPreKey.PublicKey),
			Signature: base64.StdEncoding.EncodeToString(item.KEMPreKey.Signature),
		}
	}

	return entity, nil
}

// resolveAccount looks up an account by UUID first, then by phone number.
func (s *Server) resolveAccount(r *http.Request, identifier string) (*accounts.Account, error) {
	acct, err := s.accounts.Get(r.Context(), identifier)
	if err == nil {
		return acct, nil
	}
	return s.accounts.GetByNumber(r.Context(), identifier)
}

// convertSetKeysRequest converts the API request entity to the internal
// SetKeysRequest type, decoding all base64 fields.
func convertSetKeysRequest(req *SetKeysRequestEntity) (*keys.SetKeysRequest, error) {
	result := &keys.SetKeysRequest{}

	for i := range req.PreKeys {
		pub, err := decodeBase64(req.PreKeys[i].PublicKey)
		if err != nil {
			return nil, &DecodeError{Message: "preKey publicKey", Cause: err}
		}
		result.PreKeys = append(result.PreKeys, &keys.PreKey{
			KeyID:     req.PreKeys[i].KeyId,
			PublicKey: pub,
		})
	}

	if req.SignedPreKey != nil {
		pub, err := decodeBase64(req.SignedPreKey.PublicKey)
		if err != nil {
			return nil, &DecodeError{Message: "signedPreKey publicKey", Cause: err}
		}
		sig, err := decodeBase64(req.SignedPreKey.Signature)
		if err != nil {
			return nil, &DecodeError{Message: "signedPreKey signature", Cause: err}
		}
		result.SignedPreKey = &keys.SignedPreKey{
			KeyID:     req.SignedPreKey.KeyId,
			PublicKey: pub,
			Signature: sig,
		}
	}

	for i := range req.PqPreKeys {
		pub, err := decodeBase64(req.PqPreKeys[i].PublicKey)
		if err != nil {
			return nil, &DecodeError{Message: "pqPreKey publicKey", Cause: err}
		}
		sig, err := decodeBase64(req.PqPreKeys[i].Signature)
		if err != nil {
			return nil, &DecodeError{Message: "pqPreKey signature", Cause: err}
		}
		result.KEMPreKeys = append(result.KEMPreKeys, &keys.KEMSignedPreKey{
			KeyID:     req.PqPreKeys[i].KeyId,
			PublicKey: pub,
			Signature: sig,
		})
	}

	if req.PqLastResortPreKey != nil {
		pub, err := decodeBase64(req.PqLastResortPreKey.PublicKey)
		if err != nil {
			return nil, &DecodeError{Message: "pqLastResortPreKey publicKey", Cause: err}
		}
		sig, err := decodeBase64(req.PqLastResortPreKey.Signature)
		if err != nil {
			return nil, &DecodeError{Message: "pqLastResortPreKey signature", Cause: err}
		}
		result.KEMLastResortPreKey = &keys.KEMSignedPreKey{
			KeyID:        req.PqLastResortPreKey.KeyId,
			PublicKey:    pub,
			Signature:    sig,
			IsLastResort: true,
		}
	}

	return result, nil
}
