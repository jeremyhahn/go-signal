package rest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// maxOneTimePreKeysPerUpload bounds the number of one-time (EC and KEM)
// pre-keys accepted in a single PUT /v2/keys upload, matching the Java
// Signal-Server's KeysController maximum.
const maxOneTimePreKeysPerUpload = 100

// handleGetPreKeyCount processes GET /v2/keys and returns the count of
// remaining one-time pre-keys for the authenticated user's primary device.
//
// The ?identity= query parameter selects which identity namespace (ACI or
// PNI) to report counts for. It defaults to "aci" for backwards
// compatibility, matching Java KeysController#getStatus.
func (s *Server) handleGetPreKeyCount(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	identity, err := parseIdentityQueryParam(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	state, err := s.keys.GetPreKeyCountForIdentity(r.Context(), acct, identity, deviceIDFromContext(r.Context()))
	if err != nil {
		if errors.Is(err, keys.ErrIdentityNotSet) {
			writeError(w, http.StatusBadRequest, "identity not set on account")
			return
		}
		s.logger.Error("failed to get pre-key count",
			slog.String("uuid", acct.UUID),
			slog.String("identity", identity.String()),
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
//
// The ?identity= query parameter selects which identity namespace the keys
// are uploaded into; signatures are verified against the matching identity
// key (Account.IdentityKey for ACI, Account.PhoneNumberIdentityKey for PNI).
// This mirrors Java KeysController#setKeys.
func (s *Server) handleUploadKeys(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	identity, err := parseIdentityQueryParam(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req SetKeysRequestEntity
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode upload keys request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Bound the number of one-time pre-keys accepted per upload so a single
	// request cannot inflate per-account key storage. Mirrors Java's
	// KeysController maximum-key-count check.
	if len(req.PreKeys) > maxOneTimePreKeysPerUpload || len(req.PqPreKeys) > maxOneTimePreKeysPerUpload {
		writeError(w, http.StatusBadRequest, "too many pre-keys in request")
		return
	}

	setReq, err := convertSetKeysRequest(&req)
	if err != nil {
		s.logger.Error("failed to convert keys request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid key format")
		return
	}

	identityKey := identityKeyForType(acct, identity)
	if len(identityKey) == 0 {
		writeError(w, http.StatusBadRequest, "identity key not set on account")
		return
	}

	// Validate signatures on all uploaded signed and KEM pre-keys against the
	// chosen identity's key. Mirrors Java's isEverySignedKeyValid check.
	var signedSlice []*keys.SignedPreKey
	if setReq.SignedPreKey != nil {
		signedSlice = []*keys.SignedPreKey{setReq.SignedPreKey}
	}
	if err := keys.ValidateAllSignedKeys(identityKey, signedSlice, setReq.KEMPreKeys); err != nil {
		s.logger.Warn("invalid pre-key signature on key upload",
			slog.String("uuid", acct.UUID),
			slog.String("identity", identity.String()),
			slog.String("error", err.Error()))
		writeError(w, http.StatusUnprocessableEntity, "invalid pre-key signature")
		return
	}

	if err := s.keys.StoreKeysForIdentity(r.Context(), acct, identity, deviceIDFromContext(r.Context()), setReq); err != nil {
		if errors.Is(err, keys.ErrIdentityNotSet) {
			writeError(w, http.StatusBadRequest, "identity not set on account")
			return
		}
		s.logger.Error("failed to store keys",
			slog.String("uuid", acct.UUID),
			slog.String("identity", identity.String()),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to store keys")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// parseIdentityQueryParam reads the ?identity= query parameter from r and
// returns the matching IdentityType. Empty value defaults to ACI; any other
// value besides "aci"/"pni" produces a user-facing error suitable for HTTP 400.
func parseIdentityQueryParam(r *http.Request) (accounts.IdentityType, error) {
	v := r.URL.Query().Get("identity")
	switch v {
	case "", "aci", "ACI":
		return accounts.IdentityTypeACI, nil
	case "pni", "PNI":
		return accounts.IdentityTypePNI, nil
	default:
		return 0, errInvalidIdentityQueryParam
	}
}

// identityKeyForType returns the public identity key for the requested
// namespace, or nil when the account has no value for that identity.
func identityKeyForType(acct *accounts.Account, t accounts.IdentityType) []byte {
	if acct == nil {
		return nil
	}
	switch t {
	case accounts.IdentityTypeACI:
		return acct.IdentityKey
	case accounts.IdentityTypePNI:
		return acct.PhoneNumberIdentityKey
	default:
		return nil
	}
}

// errInvalidIdentityQueryParam is returned when the ?identity= query
// parameter is neither "aci" nor "pni".
var errInvalidIdentityQueryParam = &identityQueryParamError{}

type identityQueryParamError struct{}

func (e *identityQueryParamError) Error() string {
	return "identity must be aci or pni"
}

// handleGetPreKeys processes GET /v2/keys/{identifier}/{device_id} and returns
// the pre-key bundle for the target account and device. The special device_id
// "*" returns bundles for all devices.
//
// The identifier accepts three shapes, matching Java ServiceIdentifier parsing:
//   - "ACI:<uuid>" — bundle from the ACI namespace, using Account.IdentityKey.
//   - "PNI:<uuid>" — bundle from the PNI namespace, using Account.PhoneNumberIdentityKey.
//   - bare "<uuid>" or "<E.164>" — legacy ACI default for backwards compatibility.
func (s *Server) handleGetPreKeys(w http.ResponseWriter, r *http.Request) {
	identifier := r.PathValue("identifier")
	deviceIDStr := r.PathValue("device_id")

	if identifier == "" {
		writeError(w, http.StatusBadRequest, "missing identifier")
		return
	}

	identity, bare, err := parseServiceIdentifier(identifier)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	targetAcct, err := s.resolveAccountForIdentity(r, identity, bare)
	if err != nil {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}

	identityKey := identityKeyForType(targetAcct, identity)
	if len(identityKey) == 0 {
		writeError(w, http.StatusNotFound, "identity key not set on account")
		return
	}

	resp := PreKeyResponseEntity{
		IdentityKey: base64.StdEncoding.EncodeToString(identityKey),
	}

	if deviceIDStr == "*" {
		// Return pre-keys for all devices.
		for _, dev := range targetAcct.Devices {
			item, err := s.getPreKeyResponseItem(r, targetAcct, identity, &dev)
			if err != nil {
				s.logger.Error("failed to get pre-keys for device",
					slog.String("uuid", targetAcct.UUID),
					slog.String("identity", identity.String()),
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

		item, err := s.getPreKeyResponseItem(r, targetAcct, identity, dev)
		if err != nil {
			s.logger.Error("failed to get pre-keys",
				slog.String("uuid", targetAcct.UUID),
				slog.String("identity", identity.String()),
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

// parseServiceIdentifier interprets the {identifier} path parameter, returning
// the identity namespace and the bare lookup value. It accepts:
//
//   - "ACI:<uuid>" → (IdentityTypeACI, "<uuid>")
//   - "PNI:<uuid>" → (IdentityTypePNI, "<uuid>")
//   - bare UUID or E.164 → (IdentityTypeACI, "<value>") for legacy clients
//
// Any other shape is rejected so the handler can return 400 cleanly.
func parseServiceIdentifier(s string) (accounts.IdentityType, string, error) {
	switch {
	case strings.HasPrefix(s, "ACI:"):
		bare := strings.TrimPrefix(s, "ACI:")
		if _, err := uuid.Parse(bare); err != nil {
			return 0, "", errInvalidServiceIdentifier
		}
		return accounts.IdentityTypeACI, bare, nil
	case strings.HasPrefix(s, "PNI:"):
		bare := strings.TrimPrefix(s, "PNI:")
		if _, err := uuid.Parse(bare); err != nil {
			return 0, "", errInvalidServiceIdentifier
		}
		return accounts.IdentityTypePNI, bare, nil
	}
	// Legacy bare identifier — UUID or E.164. Treat as ACI.
	if _, err := uuid.Parse(s); err == nil {
		return accounts.IdentityTypeACI, s, nil
	}
	if isValidE164(s) {
		return accounts.IdentityTypeACI, s, nil
	}
	return 0, "", errInvalidServiceIdentifier
}

// errInvalidServiceIdentifier is returned by parseServiceIdentifier for any
// shape we cannot interpret as ACI:<uuid>, PNI:<uuid>, bare UUID, or E.164.
var errInvalidServiceIdentifier = &serviceIdentifierError{}

type serviceIdentifierError struct{}

func (e *serviceIdentifierError) Error() string { return "invalid identifier" }

// resolveAccountForIdentity finds the target account for a parsed
// ServiceIdentifier. PNI lookups go through GetByPNI; ACI and bare lookups
// reuse the existing UUID-or-E.164 resolver.
func (s *Server) resolveAccountForIdentity(r *http.Request, identity accounts.IdentityType, bare string) (*accounts.Account, error) {
	if identity == accounts.IdentityTypePNI {
		return s.accounts.GetByPNI(r.Context(), bare)
	}
	return s.resolveAccount(r, bare)
}

// getPreKeyResponseItem retrieves the pre-key bundle for a single device and
// converts it to an API response entity.
func (s *Server) getPreKeyResponseItem(r *http.Request, target *accounts.Account, identity accounts.IdentityType, dev *accounts.Device) (*PreKeyResponseItemEntity, error) {
	item, err := s.keys.GetPreKeysForIdentity(r.Context(), target, identity, dev.ID)
	if err != nil {
		return nil, err
	}

	entity := &PreKeyResponseItemEntity{
		DeviceId:       dev.ID,
		RegistrationId: deviceRegistrationIDForIdentity(dev, identity),
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

// deviceRegistrationIDForIdentity returns the appropriate registration ID
// for the device in the requested namespace. Java's Device exposes
// getRegistrationId(IdentityType) which returns the PNI-specific value when
// identity == PNI; we mirror that so the bundle's registrationId matches the
// identity the client is establishing a session against.
func deviceRegistrationIDForIdentity(dev *accounts.Device, identity accounts.IdentityType) uint32 {
	if dev == nil {
		return 0
	}
	if identity == accounts.IdentityTypePNI {
		return dev.PhoneNumberIdentityRegistrationID
	}
	return dev.RegistrationID
}

// resolveAccountByServiceIdentifier parses a raw service identifier
// (ACI:<uuid>, PNI:<uuid>, bare UUID, or E.164) and resolves the matching
// account, routing PNI identifiers through the by-PNI index. It is used by the
// optional-auth (sealed-sender) middleware so that UAK lookups succeed for
// every identifier shape rather than only a bare ACI UUID.
func (s *Server) resolveAccountByServiceIdentifier(r *http.Request, raw string) (*accounts.Account, error) {
	identity, bare, err := parseServiceIdentifier(raw)
	if err != nil {
		return nil, err
	}
	return s.resolveAccountForIdentity(r, identity, bare)
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
