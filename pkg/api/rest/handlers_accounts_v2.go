package rest

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/audit"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// handleChangeNumber processes PUT /v2/accounts/number and changes the phone
// number associated with the authenticated account. This endpoint is called by
// signal-cli's finishChangeNumber command after the new number has been verified.
func (s *Server) handleChangeNumber(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		if s.audit != nil {
			s.audit.Denied(r.Context(), audit.ActionChangeNumber, "", nil)
		}
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	// Only the primary device may change the phone number. Check the device
	// that actually authenticated, not merely that a primary device exists.
	if deviceIDFromContext(r.Context()) != accounts.PrimaryDeviceID {
		if s.audit != nil {
			s.audit.Denied(r.Context(), audit.ActionChangeNumber, acct.UUID,
				map[string]any{"reason": "non-primary-device"})
		}
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

	// Proof of ownership of the NEW number is mandatory before the change is
	// applied: exactly one of a verified registration session or a recovery
	// password, each validated against req.Number. Without this gate any
	// authenticated account could seize (and thereby delete) an arbitrary
	// victim's number. Mirrors Java ChangeNumberController, which requires a
	// verified session for the target number.
	switch {
	case req.SessionID != "" && req.RecoveryPassword != "":
		writeError(w, http.StatusBadRequest, "sessionId and recoveryPassword are mutually exclusive")
		return
	case req.SessionID != "":
		if err := s.enforceVerifiedSession(r, w, req.SessionID, req.Number); err != nil {
			// enforceVerifiedSession has already written the HTTP response.
			if s.audit != nil {
				s.audit.Denied(r.Context(), audit.ActionChangeNumber, acct.UUID,
					map[string]any{"reason": "unverified-session"})
			}
			return
		}
	case req.RecoveryPassword != "":
		if err := s.enforceRecoveryPassword(r, w, req.Number, req.RecoveryPassword); err != nil {
			// enforceRecoveryPassword has already written the HTTP response.
			if s.audit != nil {
				s.audit.Denied(r.Context(), audit.ActionChangeNumber, acct.UUID,
					map[string]any{"reason": "recovery-password-mismatch"})
			}
			return
		}
	default:
		if s.audit != nil {
			s.audit.Denied(r.Context(), audit.ActionChangeNumber, acct.UUID,
				map[string]any{"reason": "missing-proof-of-ownership"})
		}
		writeError(w, http.StatusForbidden, "a verified session or recovery password is required to change the number")
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

	// Validate the per-device PNI pre-keys BEFORE mutating any state. The PNI
	// is rotated by ChangeNumber, so these keys must be re-published into the
	// new PNI namespace; validating first means a bad key aborts with nothing
	// changed.
	if len(req.DevicePniSignedPrekeys) > 0 || len(req.DevicePniPqLastResortPrekeys) > 0 {
		if len(pniIdentityKey) == 0 {
			writeError(w, http.StatusBadRequest, "pniIdentityKey is required when PNI pre-keys are provided")
			return
		}
		if !s.validateChangeNumberPniKeys(w, req, pniIdentityKey) {
			// validateChangeNumberPniKeys has already written the response.
			return
		}
	}

	updatedAcct, err := s.accounts.ChangeNumber(r.Context(), acct.UUID, req.Number, pniIdentityKey)
	if err != nil {
		s.logger.Error("failed to change phone number",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		if s.audit != nil {
			s.audit.Failure(r.Context(), audit.ActionChangeNumber, acct.UUID,
				map[string]any{"error": err.Error()})
		}
		writeError(w, http.StatusInternalServerError, "failed to change phone number")
		return
	}
	if s.audit != nil {
		// Log the OLD/NEW number prefixes only — never the full
		// number per Java's audit policy. The first 4 digits are
		// sufficient for forensic correlation without exposing PII.
		s.audit.Success(r.Context(), audit.ActionChangeNumber, acct.UUID,
			map[string]any{
				"oldNumberPrefix": prefixOrEmpty(acct.Number, 5),
				"newNumberPrefix": prefixOrEmpty(req.Number, 5),
			})
	}

	// Update the PNI registration ID on every device named in the request.
	// Each key is a device ID; the value is that device's new PNI
	// registration ID, applied to the device's PhoneNumberIdentityRegistrationID
	// (not its ACI RegistrationID). Devices that don't exist are skipped.
	for deviceIDStr, regID := range req.PniRegistrationIds {
		deviceID, perr := strconv.ParseUint(deviceIDStr, 10, 64)
		if perr != nil || deviceID == 0 {
			s.logger.Warn("ignoring invalid device ID in pniRegistrationIds",
				slog.String("uuid", acct.UUID),
				slog.String("deviceId", deviceIDStr))
			continue
		}
		if updatedAcct.GetDevice(deviceID) == nil {
			continue
		}
		pniRegID := regID
		attrs := accounts.DeviceAttributes{
			PhoneNumberIdentityRegistrationID: &pniRegID,
		}
		if _, err := s.accounts.SetDeviceAttributes(r.Context(), acct.UUID, deviceID, attrs); err != nil {
			s.logger.Error("failed to update PNI registration ID",
				slog.String("uuid", acct.UUID),
				slog.Uint64("deviceId", deviceID),
				slog.String("error", err.Error()))
		}
	}

	// Persist the per-device PNI pre-keys into the rotated PNI namespace.
	// Without this, PNI-addressed sessions to these devices would have no key
	// material after the rotation. Pre-keys were already validated above.
	if err := s.storeChangeNumberPniKeys(r.Context(), updatedAcct, req); err != nil {
		s.logger.Error("failed to store PNI pre-keys after number change",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to store PNI pre-keys")
		return
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
		PNI:            accounts.ServiceIdentifierString(accounts.IdentityTypePNI, updatedAcct.PNI),
		StorageCapable: storageCapable,
	}

	writeJSON(w, http.StatusOK, resp)
}

// validateChangeNumberPniKeys verifies the per-device PNI signed and PQ
// last-resort pre-key signatures against the supplied PNI identity key. It
// writes a 400/422 response and returns false on the first invalid key so the
// caller aborts before mutating any state.
func (s *Server) validateChangeNumberPniKeys(w http.ResponseWriter, req ChangeNumberRequest, pniIdentityKey []byte) bool {
	for _, spk := range req.DevicePniSignedPrekeys {
		pub, err := decodeBase64(spk.PublicKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid devicePniSignedPrekeys publicKey encoding")
			return false
		}
		sig, err := decodeBase64(spk.Signature)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid devicePniSignedPrekeys signature encoding")
			return false
		}
		if err := keys.ValidateSignedPreKey(pniIdentityKey, &keys.SignedPreKey{KeyID: spk.KeyId, PublicKey: pub, Signature: sig}); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid devicePniSignedPrekeys signature")
			return false
		}
	}
	for _, pqk := range req.DevicePniPqLastResortPrekeys {
		pub, err := decodeBase64(pqk.PublicKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid devicePniPqLastResortPrekeys publicKey encoding")
			return false
		}
		sig, err := decodeBase64(pqk.Signature)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid devicePniPqLastResortPrekeys signature encoding")
			return false
		}
		if err := keys.ValidateKEMSignedPreKey(pniIdentityKey, &keys.KEMSignedPreKey{KeyID: pqk.KeyId, PublicKey: pub, Signature: sig}); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid devicePniPqLastResortPrekeys signature")
			return false
		}
	}
	return true
}

// storeChangeNumberPniKeys persists the per-device PNI signed and PQ
// last-resort pre-keys into the (rotated) PNI namespace of acct. Entries for
// unknown devices are skipped. Keys must have been validated beforehand.
func (s *Server) storeChangeNumberPniKeys(ctx context.Context, acct *accounts.Account, req ChangeNumberRequest) error {
	for devIDStr, spk := range req.DevicePniSignedPrekeys {
		devID, err := strconv.ParseUint(devIDStr, 10, 64)
		if err != nil || devID == 0 || acct.GetDevice(devID) == nil {
			continue
		}
		pub, _ := decodeBase64(spk.PublicKey)
		sig, _ := decodeBase64(spk.Signature)
		signed := &keys.SignedPreKey{KeyID: spk.KeyId, PublicKey: pub, Signature: sig}
		if err := s.keys.StoreSignedPreKeyForIdentity(ctx, acct, accounts.IdentityTypePNI, devID, signed); err != nil {
			return err
		}
	}
	for devIDStr, pqk := range req.DevicePniPqLastResortPrekeys {
		devID, err := strconv.ParseUint(devIDStr, 10, 64)
		if err != nil || devID == 0 || acct.GetDevice(devID) == nil {
			continue
		}
		pub, _ := decodeBase64(pqk.PublicKey)
		sig, _ := decodeBase64(pqk.Signature)
		kemKey := &keys.KEMSignedPreKey{KeyID: pqk.KeyId, PublicKey: pub, Signature: sig}
		// Last-resort PQ key → last-resort namespace (never consumed by TakeKEM).
		if err := s.keys.StoreKEMLastResortPreKeyForIdentity(ctx, acct, accounts.IdentityTypePNI, devID, kemKey); err != nil {
			return err
		}
	}
	return nil
}
