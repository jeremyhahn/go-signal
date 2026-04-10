package rest

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
)

// maxKeyCheckElements is the maximum number of identity keys accepted in a
// single key-check request.
const maxKeyCheckElements = 1000

// handleCheckKeys processes POST /v2/keys/check and compares submitted identity
// keys against the stored account identity keys. Any mismatched keys are
// returned in the response so the client can detect identity key changes.
func (s *Server) handleCheckKeys(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req KeyCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode key check request", slog.String("error", err.Error()))
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.IdentityKeys) > maxKeyCheckElements {
		writeError(w, http.StatusBadRequest, "too many identity keys in request")
		return
	}

	mismatches := make([]IdentityKeyItem, 0)

	for _, item := range req.IdentityKeys {
		targetAcct, err := s.accounts.Get(r.Context(), item.UUID)
		if err != nil {
			s.logger.Warn("key check: account not found",
				slog.String("uuid", item.UUID),
				slog.String("error", err.Error()))
			continue
		}

		storedKeyB64 := base64.StdEncoding.EncodeToString(targetAcct.IdentityKey)
		if storedKeyB64 != item.IdentityKey {
			mismatches = append(mismatches, IdentityKeyItem{
				UUID:        item.UUID,
				IdentityKey: storedKeyB64,
			})
		}
	}

	writeJSON(w, http.StatusOK, KeyCheckResponse{
		IdentityKeyFingerprints: mismatches,
	})
}
