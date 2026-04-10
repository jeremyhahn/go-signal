package rest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
)

const (
	// profileKeyCredentialExpirationDays is the number of days from now at which
	// issued profile key credentials expire, matching the Java Signal Server's
	// EXPIRING_PROFILE_KEY_CREDENTIAL_EXPIRATION constant.
	profileKeyCredentialExpirationDays = 7

	// maxBatchIdentityCheckElements is the maximum number of ACI fingerprint
	// elements accepted in a single batch identity check request.
	maxBatchIdentityCheckElements = 1000
)

// handleGetProfileWithCredential processes
// GET /v1/profile/{identifier}/{version}/{credentialRequest} and returns the
// specified version of a user's profile along with an ExpiringProfileKeyCredential.
//
// The credentialRequest path parameter is a hex-encoded
// ProfileKeyCredentialRequest from the client. The full zkgroup issuance flow
// requires deserializing the request into a ProfileKeyCredentialRequest struct;
// until go-libsignal exports a wire deserializer for that type, this handler
// falls back to a structured stub credential that has the correct JSON shape.
func (s *Server) handleGetProfileWithCredential(w http.ResponseWriter, r *http.Request) {
	identifier := r.PathValue("identifier")
	version := r.PathValue("version")
	credentialRequest := r.PathValue("credentialRequest")

	if identifier == "" {
		writeError(w, http.StatusBadRequest, "missing identifier")
		return
	}
	if credentialRequest == "" {
		writeError(w, http.StatusBadRequest, "missing credential request")
		return
	}

	targetAcct, err := s.resolveAccount(r, identifier)
	if err != nil {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}

	profile, _ := s.profiles.Get(r.Context(), targetAcct.UUID, version)

	resp := buildProfileResponse(targetAcct, profile)

	// Compute the credential expiration time: truncate to UTC day boundary,
	// then advance by the configured expiration window. This matches the Java
	// Signal Server's behavior.
	now := time.Now().UTC()
	expirationTime := now.Truncate(24 * time.Hour).
		Add(time.Duration(profileKeyCredentialExpirationDays) * 24 * time.Hour)
	expirationTimestamp := zkgroup.TimestampFromTime(expirationTime)

	// Issue the ExpiringProfileKeyCredential. The stub path is used because
	// go-libsignal does not yet expose a wire deserializer for
	// ProfileKeyCredentialRequest. When that is added, this should be replaced
	// with the full zkgroup issuance flow using:
	//   s.certificates.GetExpiringProfileKeyCredential(ctx, aci, request, commitment, expiration)
	credResp, err := s.certificates.GetExpiringProfileKeyCredentialStub(
		r.Context(),
		targetAcct.UUID,
		expirationTimestamp,
	)
	if err != nil {
		s.logger.Error("failed to issue profile key credential",
			slog.String("uuid", targetAcct.UUID),
			slog.String("error", err.Error()),
		)
		writeError(w, http.StatusInternalServerError, "failed to issue profile key credential")
		return
	}

	resp.Credential = ProfileCredentialResponse{
		Credential:     base64.StdEncoding.EncodeToString(credResp.Credential),
		RedemptionTime: credResp.CredentialExpirationTime,
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleBatchIdentityCheck processes POST /v1/profile/identity_check/batch and
// compares ACI fingerprints against stored identity keys. A fingerprint is the
// first 4 bytes of the SHA-256 hash of the stored identity key. Any mismatches
// are returned with the stored identity key so the client can update its cache.
func (s *Server) handleBatchIdentityCheck(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req BatchIdentityCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode batch identity check request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Elements) > maxBatchIdentityCheckElements {
		writeError(w, http.StatusBadRequest, "too many elements in batch identity check")
		return
	}

	mismatches := make([]IdentityCheckResponseElement, 0)

	for _, elem := range req.Elements {
		targetAcct, err := s.accounts.Get(r.Context(), elem.UUID)
		if err != nil {
			s.logger.Warn("batch identity check: account not found",
				slog.String("uuid", elem.UUID),
				slog.String("error", err.Error()))
			continue
		}

		submittedFingerprint, err := decodeBase64(elem.Fingerprint)
		if err != nil {
			s.logger.Warn("batch identity check: invalid fingerprint encoding",
				slog.String("uuid", elem.UUID),
				slog.String("error", err.Error()))
			continue
		}

		// Compute the fingerprint of the stored identity key as the first 4
		// bytes of its SHA-256 hash.
		hash := sha256.Sum256(targetAcct.IdentityKey)
		storedFingerprint := hash[:4]

		if !fingerprintEqual(submittedFingerprint, storedFingerprint) {
			mismatches = append(mismatches, IdentityCheckResponseElement{
				UUID:        elem.UUID,
				IdentityKey: base64.StdEncoding.EncodeToString(targetAcct.IdentityKey),
			})
		}
	}

	writeJSON(w, http.StatusOK, BatchIdentityCheckResponse{
		Elements: mismatches,
	})
}

// fingerprintEqual performs a constant-time, exact-length comparison of two
// fingerprint byte slices. Both slices must have identical length; a partial
// prefix match is treated as a mismatch. This prevents two attacks:
//
//  1. Timing attack: early-return byte-by-byte comparison leaks how many
//     leading bytes match. subtle.ConstantTimeCompare eliminates this.
//  2. Prefix-match bug: a 1-byte submitted fingerprint would previously match
//     the first byte of any 4-byte stored fingerprint. Requiring an exact
//     length match closes this oracle.
func fingerprintEqual(submitted, stored []byte) bool {
	if len(submitted) != len(stored) {
		return false
	}
	if len(submitted) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare(submitted, stored) == 1
}
