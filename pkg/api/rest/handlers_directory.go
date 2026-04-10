package rest

import (
	"encoding/json"
	"net/http"
)

// maxDirectoryLookupNumbers is the maximum number of E.164 phone numbers
// accepted in a single directory lookup request.
const maxDirectoryLookupNumbers = 1024

// handleGetDirectoryAuth handles GET /v2/directory/auth and returns stub
// credentials for the contact discovery service.
func (s *Server) handleGetDirectoryAuth(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	creds, err := s.directory.GetAuthToken(r.Context(), acct.UUID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, creds)
}

// handleDirectoryLookup handles PUT /v1/directory/lookup and returns UUIDs
// for registered phone numbers. This is a simplified alternative to CDSI that
// signal-cli can use for contact discovery in test/development environments.
func (s *Server) handleDirectoryLookup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Numbers []string `json:"numbers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Numbers) > maxDirectoryLookupNumbers {
		writeError(w, http.StatusBadRequest, "too many numbers in lookup request")
		return
	}

	type contactToken struct {
		E164 string `json:"e164"`
		UUID string `json:"uuid"`
		PNI  string `json:"pni,omitempty"`
	}

	results := make([]contactToken, 0, len(req.Numbers))
	for _, number := range req.Numbers {
		acct, err := s.accounts.GetByNumber(r.Context(), number)
		if err != nil {
			continue // not registered, skip
		}
		results = append(results, contactToken{
			E164: number,
			UUID: acct.UUID,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"contacts": results,
	})
}
