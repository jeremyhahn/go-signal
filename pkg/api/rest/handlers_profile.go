package rest

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/auth"
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

	// The version becomes part of the profile storage key, so it must be a
	// bounded hex string — never containing a path separator or the reserved
	// "_latest" marker that would collide with the latest-version index.
	if !isValidProfileVersion(req.Version) {
		writeError(w, http.StatusBadRequest, "invalid profile version")
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

	// Enforce per-field ciphertext sizes, matching the exact byte lengths the
	// Java CreateProfileRequest accepts (@ExactlySize). Empty fields are treated
	// as "not provided" and skipped; a present field with a disallowed size is
	// rejected with 400 so oversized/malformed blobs never reach storage.
	if !profileFieldLenOK(name, 81, 285) {
		writeError(w, http.StatusBadRequest, "invalid name length")
		return
	}
	if !profileFieldLenOK(about, 156, 282, 540) {
		writeError(w, http.StatusBadRequest, "invalid about length")
		return
	}
	if !profileFieldLenOK(aboutEmoji, 60) {
		writeError(w, http.StatusBadRequest, "invalid aboutEmoji length")
		return
	}
	if !profileFieldLenOK(paymentAddress, 582) {
		writeError(w, http.StatusBadRequest, "invalid paymentAddress length")
		return
	}
	if !profileFieldLenOK(commitment, profileKeyCommitmentLen) {
		writeError(w, http.StatusBadRequest, "invalid commitment length")
		return
	}

	// Resolve the avatar before storing, so the stored profile carries the
	// key the upload form is signed for. Doing it the other way round writes
	// the profile without an avatar and leaves GET unable to report one.
	var (
		attrs     ProfileAvatarUploadAttributes
		change    = resolveAvatarChange(req)
		avatarKey string
	)
	switch change {
	case avatarUpdate:
		var err error
		attrs, err = s.buildAvatarUploadAttributes()
		switch {
		case errors.Is(err, errAvatarCDNNotConfigured):
			s.logger.Error("avatar upload requested but CDN is not configured",
				slog.String("uuid", acct.UUID), slog.String("error", err.Error()))
			writeError(w, http.StatusServiceUnavailable, "avatar upload is not configured")
			return
		case err != nil:
			// The CDN is configured but its credential could not be read
			// back out of protected memory: that is our failure, not a
			// deployment gap, and it must not produce a signed-with-nothing
			// upload form.
			s.logger.Error("avatar upload signing failed",
				slog.String("uuid", acct.UUID), slog.String("error", err.Error()))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		avatarKey = attrs.Key
	case avatarUnchanged:
		var err error
		avatarKey, err = s.previousAvatarKey(r.Context(), acct.UUID, req.Version)
		if err != nil {
			// Nothing is written: a failed read must not be turned into a
			// successful write that clears the avatar.
			s.logger.Error("failed to read the previous avatar for sameAvatar",
				slog.String("uuid", acct.UUID),
				slog.String("error", err.Error()))
			writeError(w, http.StatusInternalServerError, "failed to set profile")
			return
		}
	case avatarClear:
		// avatarKey stays empty: the request asked for no avatar.
	}

	profile := &profiles.Profile{
		UUID:           acct.UUID,
		Version:        req.Version,
		Name:           name,
		About:          about,
		AboutEmoji:     aboutEmoji,
		PaymentAddress: paymentAddress,
		Commitment:     commitment,
		Avatar:         avatarKey,
	}

	if err := s.profiles.Set(r.Context(), profile); err != nil {
		s.logger.Error("failed to set profile",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to set profile")
		return
	}

	if change == avatarUpdate {
		writeJSON(w, http.StatusOK, attrs)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// avatarChange is the effect a profile update has on the account's avatar.
// It mirrors Java CreateProfileRequest.AvatarChange, which is the contract
// Signal clients are written against.
type avatarChange int

const (
	// avatarClear stores no avatar, dropping whatever the version had.
	avatarClear avatarChange = iota
	// avatarUnchanged carries this version's existing avatar forward.
	avatarUnchanged
	// avatarUpdate issues a fresh upload form and stores its object name.
	avatarUpdate
)

// resolveAvatarChange maps a request onto one of the three cases, in Java's
// order (CreateProfileRequest.getAvatarChange).
//
// The order is the point: `avatar` is read FIRST, so {avatar:false,
// sameAvatar:true} CLEARS. Testing sameAvatar first instead makes that
// combination keep the avatar — the opposite of what the reference server
// gives a client asking to remove one, on a request the client is free to
// send.
func resolveAvatarChange(req SetProfileRequest) avatarChange {
	switch {
	case !req.AvatarUpload:
		return avatarClear
	case !req.SameAvatar:
		return avatarUpdate
	default:
		return avatarUnchanged
	}
}

// previousAvatarKey returns the avatar the account's profile at THIS version
// already carries, for the sameAvatar case.
//
// The version is the one about to be written, matching Java
// ProfileController.setProfile, which resolves UNCHANGED against
// profilesManager.get(accountIdentifier, request.version()). Reading the
// LATEST version instead lets a write at one version adopt another version's
// key — and because KVProfileStore.Set repoints the latest marker
// unconditionally, that same write then becomes latest, so a stale read is
// promoted rather than shadowed.
//
// Only a key under avatarObjectPrefix is carried forward, as Java does: an
// avatar this server never issued is not one it can keep signing for.
//
// Only a missing profile resolves to "no avatar": the client is asking to
// keep an avatar that does not exist yet. Every other failure — a database
// outage, a cancelled context, an unreadable row — is propagated, because the
// caller writes this value. Collapsing those into an empty key would let a
// request that explicitly said "keep my avatar" delete it during a transient
// backend failure, and report 200 for doing so.
func (s *Server) previousAvatarKey(ctx context.Context, accountUUID, version string) (string, error) {
	previous, err := s.profiles.Get(ctx, accountUUID, version)
	if err != nil {
		var notFound *profiles.ProfileNotFoundError
		if errors.As(err, &notFound) {
			return "", nil
		}
		return "", err
	}
	if previous == nil || !strings.HasPrefix(previous.Avatar, avatarObjectPrefix) {
		return "", nil
	}
	return previous.Avatar, nil
}

// avatarObjectPrefix is the CDN key prefix every avatar this server issues
// lives under. generateAvatarObjectName writes it and previousAvatarKey
// requires it, so the two cannot drift: a prefix change that reached only one
// of them would silently clear every avatar it was asked to keep.
const avatarObjectPrefix = "profiles/"

// generateAvatarObjectName returns a fresh, unguessable CDN object name for a
// profile avatar. Mirrors Java ProfileHelper.generateAvatarObjectName: 16
// random bytes, URL-safe base64, under the profiles/ prefix. Deriving the
// name from the account UUID instead would make every user's avatar object
// name a function of their account id.
func generateAvatarObjectName() (string, error) {
	var object [16]byte
	if _, err := rand.Read(object[:]); err != nil {
		return "", err
	}
	return avatarObjectPrefix + base64.URLEncoding.EncodeToString(object[:]), nil
}

// errAvatarCDNNotConfigured indicates avatar upload was requested but no S3
// CDN credentials are configured to sign the upload policy.
var errAvatarCDNNotConfigured = &avatarCDNNotConfiguredError{}

type avatarCDNNotConfiguredError struct{}

func (e *avatarCDNNotConfiguredError) Error() string { return "avatar CDN not configured" }

// buildAvatarUploadAttributes constructs a real AWS SigV4 S3 POST-policy for a
// profile-avatar upload, signed with the configured CDN credentials. It fails
// (errAvatarCDNNotConfigured) when the CDN is not configured rather than
// returning a non-functional placeholder signature.
func (s *Server) buildAvatarUploadAttributes() (ProfileAvatarUploadAttributes, error) {
	if !s.avatarCDN.Enabled() {
		return ProfileAvatarUploadAttributes{}, errAvatarCDNNotConfigured
	}

	avatarKey, err := generateAvatarObjectName()
	if err != nil {
		return ProfileAvatarUploadAttributes{}, err
	}
	now := time.Now().UTC()
	dateStamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")
	credential := s.avatarCDN.AccessKey + "/" + dateStamp + "/" + s.avatarCDN.Region + "/s3/aws4_request"

	// SigV4 POST policy: the x-amz-* fields the client submits must be bound in
	// the policy conditions so the signature covers them.
	policyJSON := fmt.Sprintf(
		`{"expiration":"%s","conditions":[{"bucket":"%s"},{"key":"%s"},{"acl":"private"},{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":"%s"},{"x-amz-date":"%s"},["starts-with","$Content-Type",""],["content-length-range",1,10485760]]}`,
		now.Add(30*time.Minute).Format(time.RFC3339),
		s.avatarCDN.Bucket,
		avatarKey,
		credential,
		amzDate,
	)
	policyB64 := base64.StdEncoding.EncodeToString([]byte(policyJSON))
	// The secret key lives in protected memory; it is opened here for the
	// single HMAC chain and the copy goes out of scope immediately. Reveal,
	// not Plaintext: Enabled() checked the secret earlier, but a destroy or
	// an enclave failure between that check and this read must fail the
	// request rather than sign the policy with an empty key and hand the
	// client an upload form S3 will reject.
	secretKey, err := s.avatarCDN.SecretKey.Reveal()
	if err != nil {
		return ProfileAvatarUploadAttributes{}, err
	}
	signature := auth.SignS3PostPolicy(secretKey, dateStamp, s.avatarCDN.Region, policyB64)

	return ProfileAvatarUploadAttributes{
		Key:        avatarKey,
		Credential: credential,
		ACL:        "private",
		Algorithm:  "AWS4-HMAC-SHA256",
		Date:       amzDate,
		Policy:     policyB64,
		Signature:  signature,
	}, nil
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
	if !isValidProfileVersion(version) {
		writeError(w, http.StatusBadRequest, "invalid profile version")
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

// isValidProfileVersion reports whether v is a syntactically valid profile
// version. Because the version is concatenated into the profile storage key
// (<uuid>/<version>), it must be a bounded token drawn from a safe character
// set — no path separators — and must not collide with the reserved "_latest"
// marker key.
func isValidProfileVersion(v string) bool {
	if len(v) == 0 || len(v) > 64 || v == profileLatestMarker {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		ok := (c >= '0' && c <= '9') ||
			(c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			c == '.' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// profileLatestMarker is the reserved version suffix the profile store uses for
// the latest-version pointer; a client-supplied version must never equal it.
const profileLatestMarker = "_latest"

// profileKeyCommitmentLen is the serialized size of a zkgroup
// ProfileKeyCommitment (Rust PROFILE_KEY_COMMITMENT_LEN).
const profileKeyCommitmentLen = 97

// profileFieldLenOK reports whether a decoded profile field is acceptable: an
// empty (not-provided) field always passes; a present field must have one of
// the allowed exact byte lengths.
func profileFieldLenOK(field []byte, allowed ...int) bool {
	if len(field) == 0 {
		return true
	}
	for _, n := range allowed {
		if len(field) == n {
			return true
		}
	}
	return false
}
