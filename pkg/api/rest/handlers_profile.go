package rest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
)

// handleSetProfile processes PUT /v1/profile and creates or updates the
// authenticated user's profile.
func (s *Server) handleSetProfile(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req SetProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode profile request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var name, about, aboutEmoji, paymentAddress, commitment []byte
	var err error

	if req.Name != "" {
		name, err = decodeBase64(req.Name)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid name encoding")
			return
		}
	}
	if req.About != "" {
		about, err = decodeBase64(req.About)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid about encoding")
			return
		}
	}
	if req.AboutEmoji != "" {
		aboutEmoji, err = decodeBase64(req.AboutEmoji)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid aboutEmoji encoding")
			return
		}
	}
	if req.PaymentAddress != "" {
		paymentAddress, err = decodeBase64(req.PaymentAddress)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid paymentAddress encoding")
			return
		}
	}
	if req.Commitment != "" {
		commitment, err = decodeBase64(req.Commitment)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid commitment encoding")
			return
		}
	}

	profile := &profiles.Profile{
		UUID:           acct.UUID,
		Version:        req.Version,
		Name:           name,
		About:          about,
		AboutEmoji:     aboutEmoji,
		PaymentAddress: paymentAddress,
		Commitment:     commitment,
	}

	if err := s.profiles.Set(r.Context(), profile); err != nil {
		s.logger.Error("failed to set profile",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to set profile")
		return
	}

	// When the client requests a new avatar upload, return S3 POST policy
	// upload attributes so signal-cli can upload the avatar to the CDN.
	if req.AvatarUpload && !req.SameAvatar {
		avatarKey := "profiles/" + acct.UUID

		now := time.Now().UTC()
		policyJSON := fmt.Sprintf(
			`{"expiration":"%s","conditions":[{"bucket":"profile-bucket"},{"key":"%s"},{"acl":"private"},["starts-with","$Content-Type",""],["content-length-range",1,10485760]]}`,
			now.Add(30*time.Minute).Format(time.RFC3339),
			avatarKey,
		)
		policyB64 := base64.StdEncoding.EncodeToString([]byte(policyJSON))

		attrs := ProfileAvatarUploadAttributes{
			Key:        avatarKey,
			Credential: "signal-test/" + now.Format("20060102") + "/us-east-1/s3/aws4_request",
			ACL:        "private",
			Algorithm:  "AWS4-HMAC-SHA256",
			Date:       now.Format("20060102T150405Z"),
			Policy:     policyB64,
			Signature:  "0000000000000000000000000000000000000000000000000000000000000000",
		}
		writeJSON(w, http.StatusOK, attrs)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetVersionedProfile processes GET /v1/profile/{identifier}/{version}
// and returns the specified version of a user's profile.
func (s *Server) handleGetVersionedProfile(w http.ResponseWriter, r *http.Request) {
	identifier := r.PathValue("identifier")
	version := r.PathValue("version")

	if identifier == "" {
		writeError(w, http.StatusBadRequest, "missing identifier")
		return
	}

	targetAcct, err := s.resolveAccount(r, identifier)
	if err != nil {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}

	profile, err := s.profiles.Get(r.Context(), targetAcct.UUID, version)
	if err != nil {
		// If no profile exists for this version, return a minimal response
		// with account-level fields. This matches the Java server behavior
		// and prevents signal-cli from logging spurious 404 warnings after
		// registration.
		writeJSON(w, http.StatusOK, buildProfileResponse(targetAcct, nil))
		return
	}

	writeJSON(w, http.StatusOK, buildProfileResponse(targetAcct, profile))
}

// handleGetProfile processes GET /v1/profile/{identifier} and returns the
// latest version of a user's profile.
func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	identifier := r.PathValue("identifier")
	if identifier == "" {
		writeError(w, http.StatusBadRequest, "missing identifier")
		return
	}

	targetAcct, err := s.resolveAccount(r, identifier)
	if err != nil {
		writeError(w, http.StatusNotFound, "account not found")
		return
	}

	profile, err := s.profiles.GetLatest(r.Context(), targetAcct.UUID)
	if err != nil {
		// If no profile exists, return a minimal response with account info.
		writeJSON(w, http.StatusOK, buildProfileResponse(targetAcct, nil))
		return
	}

	writeJSON(w, http.StatusOK, buildProfileResponse(targetAcct, profile))
}

// buildProfileResponse constructs a ProfileResponseEntity from an account and
// an optional profile. If the profile is nil, only account-level fields are
// populated.
func buildProfileResponse(acct *accounts.Account, profile *profiles.Profile) ProfileResponseEntity {
	resp := ProfileResponseEntity{
		IdentityKey:                    base64.StdEncoding.EncodeToString(acct.IdentityKey),
		UnidentifiedAccess:             base64.StdEncoding.EncodeToString(acct.UnidentifiedAccessKey),
		UnrestrictedUnidentifiedAccess: acct.UnrestrictedUnidentifiedAccess,
		UUID:                           acct.UUID,
		Badges:                         []any{},
	}

	// Populate capabilities from the primary device.
	primary := acct.PrimaryDevice()
	if primary != nil {
		resp.Capabilities = map[string]bool{
			"storage":                  primary.Capabilities.Storage,
			"transfer":                 primary.Capabilities.Transfer,
			"paymentActivation":        primary.Capabilities.PaymentActivation,
			"deleteSync":               primary.Capabilities.DeleteSync,
			"versionedExpirationTimer": primary.Capabilities.VersionedExpirationTimer,
		}
	}

	if profile != nil {
		if len(profile.Name) > 0 {
			resp.Name = base64.StdEncoding.EncodeToString(profile.Name)
		}
		if len(profile.About) > 0 {
			resp.About = base64.StdEncoding.EncodeToString(profile.About)
		}
		if len(profile.AboutEmoji) > 0 {
			resp.AboutEmoji = base64.StdEncoding.EncodeToString(profile.AboutEmoji)
		}
		resp.Avatar = profile.Avatar
		if len(profile.PaymentAddress) > 0 {
			resp.PaymentAddress = base64.StdEncoding.EncodeToString(profile.PaymentAddress)
		}
	}

	return resp
}
