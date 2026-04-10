package rest

import (
	"encoding/json"
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/keytransparency"
)

// handleKeyTransparencySearch handles POST /v1/key-transparency/search and
// returns a stub search response.
func (s *Server) handleKeyTransparencySearch(w http.ResponseWriter, r *http.Request) {
	var req keytransparency.SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := s.keyTransparency.Search(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleKeyTransparencyMonitor handles POST /v1/key-transparency/monitor and
// returns a stub monitor response.
func (s *Server) handleKeyTransparencyMonitor(w http.ResponseWriter, r *http.Request) {
	var req keytransparency.MonitorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := s.keyTransparency.Monitor(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleGetDistinguishedKey handles GET /v1/key-transparency/distinguished and
// returns a stub distinguished key response.
func (s *Server) handleGetDistinguishedKey(w http.ResponseWriter, r *http.Request) {
	resp, err := s.keyTransparency.GetDistinguishedKey(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, resp)
}
