package rest

import (
	"net/http"
	"strconv"

	"github.com/jeremyhahn/go-signal/pkg/stickers"
)

// handleGetStickerPackForm handles GET /v1/sticker/pack/form/{count} and
// returns a stub upload form with the requested number of sticker fields.
func (s *Server) handleGetStickerPackForm(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	countStr := r.PathValue("count")
	count, err := strconv.Atoi(countStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid sticker count")
		return
	}

	form, err := s.stickers.GetUploadForm(r.Context(), count)
	if err != nil {
		if _, ok := err.(*stickers.InvalidStickerCountError); ok {
			writeError(w, http.StatusBadRequest, "invalid sticker count")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, form)
}
