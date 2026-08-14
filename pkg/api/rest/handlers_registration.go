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

// registrationLockTimeRemaining is the duration in milliseconds reported to
// the client when a re-registration attempt is blocked by an active
// registration lock. The Java Signal-Server's RegistrationLockFailure reports
// timeRemaining in milliseconds (Duration.toMillis()); reporting seconds here
// caused clients to render a lock countdown ~1000x too short.
const registrationLockTimeRemaining int64 = 7 * 24 * 60 * 60 * 1000

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

	// Optional captcha verification. When a captcha solution is supplied
	// AND the deployment configured a RegistrationCaptchaManager, the
	// solution must verify before account state is mutated. A missing
	// captcha is allowed at this layer — escalation policy lives in the
	// verification session (CaptchaRequired) and fraud checker. Mirrors
	// Java RegistrationCaptchaManager.assessCaptcha + RegistrationController
	// short-circuit.
	if req.Captcha != "" {
		if s.regCaptcha == nil {
			writeError(w, http.StatusServiceUnavailable, "captcha verification not available")
			return
		}
		assess, err := s.regCaptcha.Assess(r.Context(), &req.Captcha, ipKey(r, nil))
		if err != nil {
			s.logger.Warn("registration captcha rejected",
				slog.String("ip", r.RemoteAddr),
				slog.String("error", err.Error()))
			writeError(w, http.StatusUnprocessableEntity, "captcha rejected")
			return
		}
		if assess != nil && !assess.Accepted() {
			s.logger.Warn("registration captcha not accepted",
				slog.String("ip", r.RemoteAddr))
			writeError(w, http.StatusUnprocessableEntity, "captcha not accepted")
			return
		}
	}

	// Either a verification session ID or a recovery password proves the
	// caller's authority to (re-)register the number. Java requires
	// exactly-one-of in PhoneVerificationRequest; we mirror that.
	switch {
	case req.SessionID != "" && req.RecoveryPassword != "":
		writeError(w, http.StatusBadRequest, "sessionId and recoveryPassword are mutually exclusive")
		return
	case req.SessionID != "":
		if err := s.enforceVerifiedSession(r, w, req.SessionID, number); err != nil {
			// enforceVerifiedSession has already written the HTTP response.
			return
		}
	case req.RecoveryPassword != "":
		if err := s.enforceRecoveryPassword(r, w, number, req.RecoveryPassword); err != nil {
			// enforceRecoveryPassword has already written the HTTP response.
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "either sessionId or recoveryPassword is required")
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
	pniUUID := uuid.New().String()

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
		PNI:                    pniUUID,
		Number:                 number,
		IdentityKey:            identityKeyBytes,
		PhoneNumberIdentityKey: pniIdentityKeyBytes,
		Devices:                []accounts.Device{primaryDevice},
		UnidentifiedAccessKey:  uak,
	}

	// Signal supports re-registration: if an account with the same number
	// already exists, enforce the registration lock before replacing it. The
	// displaced account is snapshotted so it can be restored if the new
	// account (or its key material) fails to persist — a failed re-registration
	// must not destroy the prior account.
	var displaced *accounts.Account
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
		displaced = existing
	}

	// restoreDisplaced re-creates the displaced account after a failed
	// re-registration so the prior account is not lost. RecreatePreserving
	// keeps the original CreatedAt/Version rather than resetting them.
	restoreDisplaced := func() {
		if displaced == nil {
			return
		}
		if restoreErr := s.accounts.RecreatePreserving(r.Context(), displaced); restoreErr != nil {
			s.logger.Error("failed to restore displaced account after failed re-registration",
				slog.String("uuid", displaced.UUID),
				slog.String("error", restoreErr.Error()))
		}
	}

	if err := s.accounts.Create(r.Context(), acct); err != nil {
		s.logger.Error("failed to create account", slog.String("error", err.Error()))
		restoreDisplaced()
		writeError(w, http.StatusInternalServerError, "failed to create account")
		return
	}

	// Store pre-keys for the primary device. On failure roll the account back
	// (and restore the displaced account) so a key-store error cannot leave a
	// live account with no key material — or destroy the prior account.
	if err := s.storeRegistrationPreKeys(r, acct, req); err != nil {
		s.logger.Error("failed to store registration pre-keys", slog.String("error", err.Error()))
		if delErr := s.accounts.Delete(r.Context(), accountUUID); delErr != nil {
			s.logger.Error("failed to roll back account after pre-key store failure",
				slog.String("uuid", accountUUID),
				slog.String("error", delErr.Error()))
		}
		// Clean up any pre-keys that were partially stored before the failure,
		// in both the ACI and PNI namespaces, so the rollback doesn't leave
		// orphaned key material behind.
		if cleanupErr := s.keys.DeleteAllForAccount(r.Context(), accountUUID); cleanupErr != nil {
			s.logger.Warn("failed to clean up ACI pre-keys after rollback",
				slog.String("uuid", accountUUID), slog.String("error", cleanupErr.Error()))
		}
		if cleanupErr := s.keys.DeleteAllForAccount(r.Context(), pniUUID); cleanupErr != nil {
			s.logger.Warn("failed to clean up PNI pre-keys after rollback",
				slog.String("pni", pniUUID), slog.String("error", cleanupErr.Error()))
		}
		restoreDisplaced()
		writeError(w, http.StatusInternalServerError, "failed to store pre-keys")
		return
	}

	// Persist any recovery password supplied via account attributes so
	// future re-registrations can skip the verification flow. Failures here
	// are logged but do not abort the registration: the account already
	// exists, and the client can re-attempt the password upload.
	s.storeAttrRecoveryPassword(r, pniUUID, req.AccountAttributes.RecoveryPassword)

	resp := AccountCreationResponse{
		UUID:           accountUUID,
		PNI:            accounts.ServiceIdentifierString(accounts.IdentityTypePNI, pniUUID),
		StorageCapable: capabilityValue(req.AccountAttributes.Capabilities, "storage"),
	}
	writeJSON(w, http.StatusOK, resp)
}

// enforceRecoveryPassword verifies a base64-encoded registration recovery
// password against the manager's stored hash for the number's PNI. On any
// failure it writes the HTTP response and returns a non-nil sentinel error;
// callers must return immediately.
func (s *Server) enforceRecoveryPassword(r *http.Request, w http.ResponseWriter, number, encoded string) error {
	if s.recoveryPasswords == nil {
		writeError(w, http.StatusBadRequest, "recoveryPassword not supported by this server")
		return errRecoveryPasswordUnsupported
	}

	pwd, err := decodeBase64(encoded)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in recoveryPassword")
		return err
	}

	existing, err := s.accounts.GetByNumber(r.Context(), number)
	if err != nil {
		s.logger.Warn("recovery password registration: no existing account",
			slog.String("number", redactNumber(number)),
			slog.String("error", err.Error()))
		writeError(w, http.StatusForbidden, "recoveryPassword cannot register a new number")
		return err
	}

	ok, err := s.recoveryPasswords.Verify(r.Context(), existing.PNI, pwd)
	if err != nil {
		s.logger.Error("failed to verify recovery password",
			slog.String("pni", existing.PNI),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to verify recovery password")
		return err
	}
	if !ok {
		writeError(w, http.StatusForbidden, "recoveryPassword does not match")
		return errRecoveryPasswordMismatch
	}
	return nil
}

// storeAttrRecoveryPassword stores a recovery password attached to an account
// attributes payload. Empty input is a no-op; non-empty input is decoded and
// passed to the manager. All failures are logged at warn level; the caller
// flow continues regardless because the account record already exists.
func (s *Server) storeAttrRecoveryPassword(r *http.Request, pni, encoded string) {
	if encoded == "" || s.recoveryPasswords == nil {
		return
	}
	pwd, err := decodeBase64(encoded)
	if err != nil {
		s.logger.Warn("ignoring invalid base64 recoveryPassword on registration",
			slog.String("error", err.Error()))
		return
	}
	if err := s.recoveryPasswords.Store(r.Context(), pni, pwd); err != nil {
		s.logger.Warn("failed to store recovery password",
			slog.String("pni", pni),
			slog.String("error", err.Error()))
	}
}

// errRecoveryPasswordUnsupported and errRecoveryPasswordMismatch are sentinel
// errors returned by enforceRecoveryPassword to signal the HTTP response has
// already been written. Callers do not consume them beyond the != nil check.
var (
	errRecoveryPasswordUnsupported = &recoveryPasswordSentinelError{Reason: "unsupported"}
	errRecoveryPasswordMismatch    = &recoveryPasswordSentinelError{Reason: "mismatch"}
)

type recoveryPasswordSentinelError struct{ Reason string }

func (e *recoveryPasswordSentinelError) Error() string { return "recovery password " + e.Reason }

// storeRegistrationPreKeys persists the signed and PQ last-resort pre-keys
// submitted during registration for BOTH the ACI and PNI identity namespaces.
// The PNI keys are validated alongside the ACI keys in validateRegistrationKeys
// but must also be persisted here, otherwise PNI pre-key lookups fail
// immediately after a successful registration.
func (s *Server) storeRegistrationPreKeys(r *http.Request, acct *accounts.Account, req RegistrationRequest) error {
	ctx := r.Context()
	deviceID := uint64(accounts.PrimaryDeviceID)
	accountUUID := acct.UUID

	// --- ACI namespace ---
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
	// Last-resort keys go in the last-resort namespace so they are not consumed
	// (deleted) by TakeKEM during session establishment.
	if err := s.keys.StoreKEMLastResortPreKey(ctx, accountUUID, deviceID, aciPqKey); err != nil {
		return err
	}

	// --- PNI namespace ---
	pniSignedPub, err := decodeBase64(req.PniSignedPreKey.PublicKey)
	if err != nil {
		return &DecodeError{Message: "pniSignedPreKey publicKey", Cause: err}
	}
	pniSignedSig, err := decodeBase64(req.PniSignedPreKey.Signature)
	if err != nil {
		return &DecodeError{Message: "pniSignedPreKey signature", Cause: err}
	}
	pniSigned := &keys.SignedPreKey{
		KeyID:     req.PniSignedPreKey.KeyId,
		PublicKey: pniSignedPub,
		Signature: pniSignedSig,
	}
	if err := s.keys.StoreSignedPreKeyForIdentity(ctx, acct, accounts.IdentityTypePNI, deviceID, pniSigned); err != nil {
		return err
	}

	pniPqPub, err := decodeBase64(req.PniPqLastResortPreKey.PublicKey)
	if err != nil {
		return &DecodeError{Message: "pniPqLastResortPreKey publicKey", Cause: err}
	}
	pniPqSig, err := decodeBase64(req.PniPqLastResortPreKey.Signature)
	if err != nil {
		return &DecodeError{Message: "pniPqLastResortPreKey signature", Cause: err}
	}
	pniPqKey := &keys.KEMSignedPreKey{
		KeyID:     req.PniPqLastResortPreKey.KeyId,
		PublicKey: pniPqPub,
		Signature: pniPqSig,
	}
	if err := s.keys.StoreKEMLastResortPreKeyForIdentity(ctx, acct, accounts.IdentityTypePNI, deviceID, pniPqKey); err != nil {
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
