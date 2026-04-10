package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/spam"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// registrationLockTimeRemaining is the duration in seconds reported to the
// client when a re-registration attempt is blocked by an active registration
// lock. It mirrors the Signal server's 7-day lock window expressed in seconds.
const registrationLockTimeRemaining int64 = 7 * 24 * 60 * 60

// handleRegistration processes POST /v1/registration requests. It creates a
// new account with a generated UUID, stores the identity key and primary
// device, and persists the initial pre-keys.
func (s *Server) handleRegistration(w http.ResponseWriter, r *http.Request) {
	number, password, ok := r.BasicAuth()
	if !ok || number == "" || password == "" {
		writeError(w, http.StatusBadRequest, "missing basic auth credentials")
		return
	}

	if !isValidE164(number) {
		writeError(w, http.StatusBadRequest, "invalid phone number format")
		return
	}

	// Evaluate registration fraud heuristics before processing the request.
	if s.fraudChecker != nil {
		fraudReq := &spam.RegistrationFraudRequest{
			IP:          r.RemoteAddr,
			PhoneNumber: number,
			UserAgent:   r.Header.Get("User-Agent"),
			Timestamp:   time.Now(),
		}
		if s.fraudChecker.Check(r.Context(), fraudReq) {
			s.logger.Warn("registration blocked by fraud checker",
				slog.String("ip", r.RemoteAddr),
				slog.String("number", redactNumber(number)))
			writeError(w, http.StatusForbidden, "registration not allowed")
			return
		}
	}

	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode registration request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Require a verification session ID in the request body. The session must
	// exist, must not be expired, must belong to the number being registered,
	// and must be in the Verified state. This mirrors the Java server's
	// RegistrationController#register verification gate.
	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "missing sessionId")
		return
	}
	if err := s.enforceVerifiedSession(r, w, req.SessionID, number); err != nil {
		// enforceVerifiedSession has already written the HTTP response.
		return
	}

	identityKeyBytes, err := decodeBase64(req.IdentityKey)
	if err != nil {
		s.logger.Error("failed to decode identity key", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid aciIdentityKey encoding")
		return
	}

	pniIdentityKeyBytes, err := decodeBase64(req.PniIdentityKey)
	if err != nil {
		s.logger.Error("failed to decode PNI identity key", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid pniIdentityKey encoding")
		return
	}

	aciSignedPub, err := decodeBase64(req.AciSignedPreKey.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid aciSignedPreKey publicKey encoding")
		return
	}
	aciSignedSig, err := decodeBase64(req.AciSignedPreKey.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid aciSignedPreKey signature encoding")
		return
	}

	var uak []byte
	if req.AccountAttributes.UnidentifiedAccessKey != "" {
		uak, err = decodeBase64(req.AccountAttributes.UnidentifiedAccessKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid unidentifiedAccessKey encoding")
			return
		}
	}

	// Validate all signed pre-key signatures against the submitted identity
	// keys. Any invalid signature results in 422 Unprocessable Entity, which
	// matches the Java Signal-Server behaviour (isEverySignedKeyValid).
	if err := s.validateRegistrationKeys(w, identityKeyBytes, pniIdentityKeyBytes, req,
		aciSignedPub, aciSignedSig); err != nil {
		// validateRegistrationKeys has already written the HTTP response.
		return
	}

	accountUUID := uuid.New().String()
	pni := "PNI:" + uuid.New().String()

	// Build the primary device with the ACI signed pre-key.
	primaryDevice := accounts.Device{
		ID:                                accounts.PrimaryDeviceID,
		Name:                              req.AccountAttributes.Name,
		AuthToken:                         password,
		FetchesMessages:                   req.AccountAttributes.FetchesMessages,
		RegistrationID:                    req.AccountAttributes.RegistrationId,
		PhoneNumberIdentityRegistrationID: req.AccountAttributes.PniRegistrationId,
		SignedPreKey: &accounts.SignedPreKey{
			KeyID:     req.AciSignedPreKey.KeyId,
			PublicKey: aciSignedPub,
			Signature: aciSignedSig,
		},
		Capabilities: deviceCapabilitiesFromMap(req.AccountAttributes.Capabilities),
	}

	acct := &accounts.Account{
		UUID:                   accountUUID,
		Number:                 number,
		IdentityKey:            identityKeyBytes,
		PhoneNumberIdentityKey: pniIdentityKeyBytes,
		Devices:                []accounts.Device{primaryDevice},
		UnidentifiedAccessKey:  uak,
	}

	// Signal supports re-registration: if an account with the same number
	// already exists, enforce the registration lock before replacing it.
	if existing, err := s.accounts.GetByNumber(r.Context(), number); err == nil {
		if existing.RegistrationLockHash != nil {
			// The existing account has an active registration lock. The
			// incoming request must supply the correct PIN; otherwise we
			// return 423 Locked so the client knows to prompt for the PIN.
			pin := req.AccountAttributes.RegistrationLock
			if !existing.RegistrationLockHash.Verify(pin) {
				s.logger.Warn("registration blocked by registration lock",
					slog.String("number", redactNumber(number)))
				writeJSON(w, http.StatusLocked, RegistrationLockErrorResponse{
					TimeRemaining: registrationLockTimeRemaining,
				})
				return
			}
		}

		if delErr := s.accounts.Delete(r.Context(), existing.UUID); delErr != nil {
			s.logger.Error("failed to delete existing account during re-registration",
				slog.String("number", redactNumber(number)),
				slog.String("error", delErr.Error()))
			writeError(w, http.StatusInternalServerError, "failed to create account")
			return
		}
	}

	if err := s.accounts.Create(r.Context(), acct); err != nil {
		s.logger.Error("failed to create account", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to create account")
		return
	}

	// Store pre-keys for the primary device.
	if err := s.storeRegistrationPreKeys(r, accountUUID, req); err != nil {
		s.logger.Error("failed to store registration pre-keys", slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to store pre-keys")
		return
	}

	resp := AccountCreationResponse{
		UUID:           accountUUID,
		PNI:            pni,
		StorageCapable: capabilityValue(req.AccountAttributes.Capabilities, "storage"),
	}
	writeJSON(w, http.StatusOK, resp)
}

// storeRegistrationPreKeys persists the signed and PQ last-resort pre-keys
// submitted during registration.
func (s *Server) storeRegistrationPreKeys(r *http.Request, accountUUID string, req RegistrationRequest) error {
	ctx := r.Context()
	deviceID := uint64(accounts.PrimaryDeviceID)

	aciSignedPub, _ := decodeBase64(req.AciSignedPreKey.PublicKey)
	aciSignedSig, _ := decodeBase64(req.AciSignedPreKey.Signature)

	aciSigned := &keys.SignedPreKey{
		KeyID:     req.AciSignedPreKey.KeyId,
		PublicKey: aciSignedPub,
		Signature: aciSignedSig,
	}
	if err := s.keys.StoreSignedPreKey(ctx, accountUUID, deviceID, aciSigned); err != nil {
		return err
	}

	aciPqPub, err := decodeBase64(req.AciPqLastResortPreKey.PublicKey)
	if err != nil {
		return &DecodeError{Message: "aciPqLastResortPreKey publicKey", Cause: err}
	}
	aciPqSig, err := decodeBase64(req.AciPqLastResortPreKey.Signature)
	if err != nil {
		return &DecodeError{Message: "aciPqLastResortPreKey signature", Cause: err}
	}

	aciPqKey := &keys.KEMSignedPreKey{
		KeyID:     req.AciPqLastResortPreKey.KeyId,
		PublicKey: aciPqPub,
		Signature: aciPqSig,
	}
	if err := s.keys.StoreKEMPreKeys(ctx, accountUUID, deviceID, []*keys.KEMSignedPreKey{aciPqKey}); err != nil {
		return err
	}

	return nil
}

// validateRegistrationKeys verifies all signed pre-key signatures submitted
// during registration. It checks:
//   - aciSignedPreKey against aciIdentityKey
//   - pniSignedPreKey against pniIdentityKey
//   - aciPqLastResortPreKey against aciIdentityKey
//   - pniPqLastResortPreKey against pniIdentityKey
//
// On the first validation failure it writes HTTP 422 and returns a non-nil
// sentinel error. The caller must return immediately without writing further
// responses.
func (s *Server) validateRegistrationKeys(
	w http.ResponseWriter,
	aciIdentityKey, pniIdentityKey []byte,
	req RegistrationRequest,
	aciSignedPub, aciSignedSig []byte,
) error {
	// Decode PNI signed pre-key fields needed for signature validation.
	pniSignedPub, err := decodeBase64(req.PniSignedPreKey.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pniSignedPreKey publicKey encoding")
		return err
	}
	pniSignedSig, err := decodeBase64(req.PniSignedPreKey.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pniSignedPreKey signature encoding")
		return err
	}

	aciPqPub, err := decodeBase64(req.AciPqLastResortPreKey.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid aciPqLastResortPreKey publicKey encoding")
		return err
	}
	aciPqSig, err := decodeBase64(req.AciPqLastResortPreKey.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid aciPqLastResortPreKey signature encoding")
		return err
	}

	pniPqPub, err := decodeBase64(req.PniPqLastResortPreKey.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pniPqLastResortPreKey publicKey encoding")
		return err
	}
	pniPqSig, err := decodeBase64(req.PniPqLastResortPreKey.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid pniPqLastResortPreKey signature encoding")
		return err
	}

	// ACI signed pre-key against ACI identity key.
	aciSPK := &keys.SignedPreKey{
		KeyID:     req.AciSignedPreKey.KeyId,
		PublicKey: aciSignedPub,
		Signature: aciSignedSig,
	}
	if err := keys.ValidateSignedPreKey(aciIdentityKey, aciSPK); err != nil {
		s.logger.Warn("invalid aciSignedPreKey signature", slog.String("error", err.Error()))
		writeError(w, http.StatusUnprocessableEntity, "invalid aciSignedPreKey signature")
		return err
	}

	// PNI signed pre-key against PNI identity key.
	pniSPK := &keys.SignedPreKey{
		KeyID:     req.PniSignedPreKey.KeyId,
		PublicKey: pniSignedPub,
		Signature: pniSignedSig,
	}
	if err := keys.ValidateSignedPreKey(pniIdentityKey, pniSPK); err != nil {
		s.logger.Warn("invalid pniSignedPreKey signature", slog.String("error", err.Error()))
		writeError(w, http.StatusUnprocessableEntity, "invalid pniSignedPreKey signature")
		return err
	}

	// ACI PQ last-resort pre-key against ACI identity key.
	aciPqKey := &keys.KEMSignedPreKey{
		KeyID:     req.AciPqLastResortPreKey.KeyId,
		PublicKey: aciPqPub,
		Signature: aciPqSig,
	}
	if err := keys.ValidateKEMSignedPreKey(aciIdentityKey, aciPqKey); err != nil {
		s.logger.Warn("invalid aciPqLastResortPreKey signature", slog.String("error", err.Error()))
		writeError(w, http.StatusUnprocessableEntity, "invalid aciPqLastResortPreKey signature")
		return err
	}

	// PNI PQ last-resort pre-key against PNI identity key.
	pniPqKey := &keys.KEMSignedPreKey{
		KeyID:     req.PniPqLastResortPreKey.KeyId,
		PublicKey: pniPqPub,
		Signature: pniPqSig,
	}
	if err := keys.ValidateKEMSignedPreKey(pniIdentityKey, pniPqKey); err != nil {
		s.logger.Warn("invalid pniPqLastResortPreKey signature", slog.String("error", err.Error()))
		writeError(w, http.StatusUnprocessableEntity, "invalid pniPqLastResortPreKey signature")
		return err
	}

	return nil
}

// deviceCapabilitiesFromMap converts a JSON capabilities map to the internal
// DeviceCapabilities struct.
func deviceCapabilitiesFromMap(caps map[string]bool) accounts.DeviceCapabilities {
	return accounts.DeviceCapabilities{
		Storage:                  caps["storage"],
		Transfer:                 caps["transfer"],
		PaymentActivation:        caps["paymentActivation"],
		DeleteSync:               caps["deleteSync"],
		VersionedExpirationTimer: caps["versionedExpirationTimer"],
	}
}

// capabilityValue returns the boolean value for a capability key, defaulting to
// false if the map is nil or the key is absent.
func capabilityValue(caps map[string]bool, key string) bool {
	if caps == nil {
		return false
	}
	return caps[key]
}

// enforceVerifiedSession checks that sessionID refers to a verification session
// that is not expired, belongs to number, and has Verified == true.
//
// On any failure it writes the appropriate HTTP error response and returns a
// non-nil sentinel error; the caller must return immediately without writing
// further responses.
func (s *Server) enforceVerifiedSession(r *http.Request, w http.ResponseWriter, sessionID, number string) error {
	session, err := s.verification.GetSession(r.Context(), sessionID)
	if err != nil {
		var notFound *verification.SessionNotFoundError
		var expired *verification.SessionExpiredError
		switch {
		case errors.As(err, &notFound):
			s.logger.Warn("registration rejected: session not found",
				slog.String("sessionId", sessionID))
			writeError(w, http.StatusForbidden, "verification session not found")
		case errors.As(err, &expired):
			s.logger.Warn("registration rejected: session expired",
				slog.String("sessionId", sessionID))
			writeError(w, http.StatusForbidden, "verification session expired")
		default:
			s.logger.Error("registration rejected: session lookup error",
				slog.String("sessionId", sessionID),
				slog.String("error", err.Error()))
			writeError(w, http.StatusInternalServerError, "failed to look up verification session")
		}
		return err
	}

	if session.Number != number {
		s.logger.Warn("registration rejected: session number mismatch",
			slog.String("sessionId", sessionID),
			slog.String("sessionNumber", session.Number),
			slog.String("requestNumber", number))
		writeError(w, http.StatusForbidden, "verification session does not match phone number")
		return &SessionPhoneNumberMismatchError{SessionID: sessionID}
	}

	if !session.Verified {
		s.logger.Warn("registration rejected: session not verified",
			slog.String("sessionId", sessionID))
		writeError(w, http.StatusForbidden, "phone number not verified")
		return &SessionNotVerifiedError{SessionID: sessionID}
	}

	return nil
}
