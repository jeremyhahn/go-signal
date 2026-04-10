package rest

import (
	"io"
	"net/http"
	"strconv"

	"github.com/google/uuid"
)

// handleAttachmentUploadForm handles GET /v4/attachments/form/upload and
// returns an upload descriptor pointing to the built-in CDN3 TUS endpoint.
func (s *Server) handleAttachmentUploadForm(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	key := uuid.NewString()

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	uploadURL := scheme + "://" + r.Host + "/cdn3/attachments/" + key

	descriptor := AttachmentDescriptorV3{
		CDN:                  3,
		Key:                  "attachments/" + key,
		Headers:              map[string]string{},
		SignedUploadLocation: uploadURL,
	}
	writeJSON(w, http.StatusOK, descriptor)
}

// handleCDNUpload implements a TUS-compatible resumable upload endpoint at
// /cdn3/{rest...}. Uploads are stored in the attachment store when available,
// otherwise accepted and discarded (dev mode).
func (s *Server) handleCDNUpload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleCDNUploadCreate(w, r)
	case http.MethodPatch:
		s.handleCDNUploadPatch(w, r)
	case http.MethodHead:
		s.handleCDNUploadHead(w, r)
	case http.MethodPut:
		s.handleCDNUploadPut(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCDNUploadCreate(w http.ResponseWriter, r *http.Request) {
	sessionID := uuid.NewString()

	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	location := scheme + "://" + r.Host + "/cdn3/upload/" + sessionID

	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read request body")
		return
	}

	w.Header().Set("Location", location)
	w.Header().Set("Tus-Resumable", "1.0.0")
	w.Header().Set("Upload-Offset", "0")
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleCDNUploadPatch(w http.ResponseWriter, r *http.Request) {
	// Extract the attachment key from the URL path.
	key := r.PathValue("rest")
	if key == "" {
		key = "unknown/" + uuid.NewString()
	}

	var n int64
	if s.attachmentStore != nil {
		size := int64(0)
		if lenStr := r.Header.Get("Upload-Length"); lenStr != "" {
			if parsed, err := strconv.ParseInt(lenStr, 10, 64); err == nil {
				size = parsed
			}
		}
		if err := s.attachmentStore.Put(r.Context(), key, r.Body, size); err != nil {
			s.logger.Error("attachment upload failed", "key", key, "error", err.Error())
			writeError(w, http.StatusInternalServerError, "upload failed")
			return
		}
		n = size
	} else {
		n, _ = io.Copy(io.Discard, r.Body)
	}

	startOffset := int64(0)
	if offsetStr := r.Header.Get("Upload-Offset"); offsetStr != "" {
		if parsed, err := strconv.ParseInt(offsetStr, 10, 64); err == nil {
			startOffset = parsed
		}
	}
	newOffset := startOffset + n

	w.Header().Set("Tus-Resumable", "1.0.0")
	w.Header().Set("Upload-Offset", strconv.FormatInt(newOffset, 10))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCDNUploadHead(w http.ResponseWriter, r *http.Request) {
	length := r.Header.Get("Upload-Length")
	if length == "" {
		length = "0"
	}

	w.Header().Set("Tus-Resumable", "1.0.0")
	w.Header().Set("Upload-Offset", length)
	w.Header().Set("Upload-Length", length)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleCDNUploadPut(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("rest")
	if key == "" {
		key = "unknown/" + uuid.NewString()
	}

	if s.attachmentStore != nil {
		if err := s.attachmentStore.Put(r.Context(), key, r.Body, r.ContentLength); err != nil {
			s.logger.Error("attachment upload failed", "key", key, "error", err.Error())
			writeError(w, http.StatusInternalServerError, "upload failed")
			return
		}
	} else {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to read request body")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// handleCDNDownload serves attachment downloads from the attachment store.
func (s *Server) handleCDNDownload(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("rest")
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing attachment key")
		return
	}

	if s.attachmentStore == nil {
		writeError(w, http.StatusNotFound, "attachment storage not configured")
		return
	}

	reader, size, err := s.attachmentStore.Get(r.Context(), key)
	if err != nil {
		writeError(w, http.StatusNotFound, "attachment not found")
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, reader)
}
