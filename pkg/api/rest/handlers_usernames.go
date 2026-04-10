package rest

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// handleReserveUsernameHash processes PUT /v1/accounts/username_hash/reserve
// and attempts to reserve one of the provided username hashes.
func (s *Server) handleReserveUsernameHash(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req UsernameHashReserveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode username hash reserve request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	const (
		maxUsernameHashes  = 20
		usernameHashLength = 32
	)

	if len(req.UsernameHashes) == 0 {
		writeError(w, http.StatusBadRequest, "usernameHashes must not be empty")
		return
	}
	if len(req.UsernameHashes) > maxUsernameHashes {
		writeError(w, http.StatusBadRequest, "too many username hashes")
		return
	}

	hashes := make([][]byte, len(req.UsernameHashes))
	for i, h := range req.UsernameHashes {
		decoded, err := decodeBase64(h)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid base64 in usernameHashes")
			return
		}
		if len(decoded) != usernameHashLength {
			writeError(w, http.StatusBadRequest, "invalid username hash length")
			return
		}
		hashes[i] = decoded
	}

	selectedHash, _, err := s.usernames.ReserveHash(r.Context(), acct.UUID, hashes)
	if err != nil {
		if _, ok := err.(*usernames.UsernameHashConflictError); ok {
			writeError(w, http.StatusConflict, "all username hashes are taken")
			return
		}
		s.logger.Error("failed to reserve username hash",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to reserve username hash")
		return
	}

	writeJSON(w, http.StatusOK, UsernameHashReserveResponse{
		UsernameHash: base64.StdEncoding.EncodeToString(selectedHash),
	})
}

// handleConfirmUsernameHash processes PUT /v1/accounts/username_hash/confirm
// and confirms a previously reserved username hash.
func (s *Server) handleConfirmUsernameHash(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req UsernameHashConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode username hash confirm request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	hash, err := decodeBase64(req.UsernameHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in usernameHash")
		return
	}

	if req.ReservationToken == "" {
		writeError(w, http.StatusBadRequest, "reservationToken must not be empty")
		return
	}

	if err := s.usernames.ConfirmHash(r.Context(), acct.UUID, hash, req.ReservationToken); err != nil {
		if _, ok := err.(*usernames.InvalidReservationTokenError); ok {
			writeError(w, http.StatusConflict, "invalid or expired reservation")
			return
		}
		s.logger.Error("failed to confirm username hash",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to confirm username hash")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteUsernameHash processes DELETE /v1/accounts/username_hash and
// removes the confirmed username hash for the authenticated account.
func (s *Server) handleDeleteUsernameHash(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	if err := s.usernames.DeleteHash(r.Context(), acct.UUID); err != nil {
		if _, ok := err.(*usernames.UsernameNotFoundError); ok {
			writeError(w, http.StatusNotFound, "no username hash set")
			return
		}
		s.logger.Error("failed to delete username hash",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to delete username hash")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleLookupUsernameHash processes GET /v1/accounts/username_hash/{usernameHash}
// and returns the UUID associated with the given username hash. Both
// authenticated and unauthenticated requests are accepted; rate limiting by
// IP provides enumeration protection.
func (s *Server) handleLookupUsernameHash(w http.ResponseWriter, r *http.Request) {
	hashStr := r.PathValue("usernameHash")
	if hashStr == "" {
		writeError(w, http.StatusBadRequest, "usernameHash is required")
		return
	}

	hash, err := base64.URLEncoding.DecodeString(hashStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in usernameHash")
		return
	}

	accountUUID, err := s.usernames.LookupByHash(r.Context(), hash)
	if err != nil {
		if _, ok := err.(*usernames.UsernameNotFoundError); ok {
			writeError(w, http.StatusNotFound, "username hash not found")
			return
		}
		s.logger.Error("failed to lookup username hash",
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to lookup username hash")
		return
	}

	writeJSON(w, http.StatusOK, UsernameHashLookupResponse{
		UUID: accountUUID,
	})
}

// handleSetUsernameLink processes PUT /v1/accounts/username_link and creates
// or replaces the username link for the authenticated account.
func (s *Server) handleSetUsernameLink(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req UsernameLinkSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode username link request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.UsernameLinkEncryptedValue == "" {
		writeError(w, http.StatusBadRequest, "usernameLinkEncryptedValue must not be empty")
		return
	}

	const maxUsernameLinkCiphertext = 128

	encrypted, err := decodeBase64(req.UsernameLinkEncryptedValue)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid base64 in usernameLinkEncryptedValue")
		return
	}
	if len(encrypted) > maxUsernameLinkCiphertext {
		writeError(w, http.StatusBadRequest, "username link ciphertext too large")
		return
	}

	handle := uuid.New().String()

	link := &usernames.UsernameLink{
		UUID:               acct.UUID,
		UsernameLinkHandle: handle,
		EncryptedUsername:  encrypted,
	}

	if err := s.usernames.SetLink(r.Context(), link); err != nil {
		s.logger.Error("failed to set username link",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to set username link")
		return
	}

	writeJSON(w, http.StatusOK, UsernameLinkSetResponse{
		UsernameLinkHandle: handle,
	})
}

// handleDeleteUsernameLink processes DELETE /v1/accounts/username_link and
// removes the username link for the authenticated account.
func (s *Server) handleDeleteUsernameLink(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	if err := s.usernames.DeleteLink(r.Context(), acct.UUID); err != nil {
		if _, ok := err.(*usernames.UsernameLinkNotFoundError); ok {
			writeError(w, http.StatusNotFound, "no username link set")
			return
		}
		s.logger.Error("failed to delete username link",
			slog.String("uuid", acct.UUID),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to delete username link")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleLookupUsernameLink processes GET /v1/accounts/username_link/{uuid}
// and returns the encrypted username for the given link handle. Both
// authenticated and unauthenticated requests are accepted; rate limiting by
// IP provides enumeration protection.
func (s *Server) handleLookupUsernameLink(w http.ResponseWriter, r *http.Request) {
	handle := r.PathValue("uuid")
	if handle == "" {
		writeError(w, http.StatusBadRequest, "link handle is required")
		return
	}

	link, err := s.usernames.GetLink(r.Context(), handle)
	if err != nil {
		if _, ok := err.(*usernames.UsernameLinkNotFoundError); ok {
			writeError(w, http.StatusNotFound, "username link not found")
			return
		}
		s.logger.Error("failed to lookup username link",
			slog.String("handle", handle),
			slog.String("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "failed to lookup username link")
		return
	}

	writeJSON(w, http.StatusOK, UsernameLinkLookupResponse{
		UsernameLinkEncryptedValue: base64.StdEncoding.EncodeToString(link.EncryptedUsername),
	})
}
