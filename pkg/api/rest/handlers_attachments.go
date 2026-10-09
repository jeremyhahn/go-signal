package rest

import (
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/extservice/common"
)

// isSafeCDNKey reports whether a client-supplied CDN object key is safe to pass
// to the attachment store. It rejects empty keys, absolute paths, backslashes,
// NUL bytes, and any "."/".." path segment so that a crafted key cannot escape
// a filesystem-backed store's root directory (path traversal).
func isSafeCDNKey(key string) bool {
	if key == "" || strings.HasPrefix(key, "/") || strings.ContainsAny(key, "\\\x00") {
		return false
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// handleAttachmentUploadForm handles GET /v4/attachments/form/upload and
// returns an upload descriptor. When an external TUS server is configured
// the descriptor carries an HMAC-signed Authorization header so the TUS
// server can validate the upload was authorized by Signal. Otherwise the
// embedded /cdn3 route is used (dev mode).
//
// Mirrors Java AttachmentControllerV4.getAttachmentUploadForm — same
// AttachmentDescriptorV3 shape on the wire.
func (s *Server) handleAttachmentUploadForm(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	key := uuid.NewString()
	attachmentKey := "attachments/" + key
	headers := map[string]string{}
	var uploadURL string

	if s.tusGenerator != nil && s.tusURI != "" {
		// External TUS server mode (Java parity).
		creds, err := s.tusGenerator.Generate(attachmentKey)
		if err != nil {
			s.logger.Error("attachment credentials failed", "error", err.Error())
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		// The TUS credential is opened only to build the Authorization
		// header the client forwards, then wiped. An unavailable credential
		// fails the request rather than emitting a header with an empty
		// password the TUS server would reject.
		//
		// Assembled by the shared helper rather than open-coded: the previous
		// spelling revealed the password into a Go string and then built two
		// more — the `user:pass` concatenation and its base64 — none of which
		// can be wiped, and all of which outlived the request.
		auth := common.BasicAuthHeaderCredential(creds.Username, creds.Password)
		creds.Destroy()
		if auth == "" {
			s.logger.Error("attachment credentials unavailable")
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		headers["Authorization"] = auth
		headers["Upload-Metadata"] = "filename " + base64.StdEncoding.EncodeToString([]byte(key))
		uploadURL = s.tusURI + "/attachments"
	} else {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		uploadURL = scheme + "://" + r.Host + "/cdn3/" + attachmentKey
	}

	descriptor := AttachmentDescriptorV3{
		CDN:                  3,
		Key:                  attachmentKey,
		Headers:              headers,
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
	// Extract the attachment key from the URL path and reject any key that
	// could escape the store's namespace (path traversal).
	key := r.PathValue("rest")
	if !isSafeCDNKey(key) {
		writeError(w, http.StatusBadRequest, "invalid attachment key")
		return
	}

	startOffset := int64(0)
	if offsetStr := r.Header.Get("Upload-Offset"); offsetStr != "" {
		if parsed, err := strconv.ParseInt(offsetStr, 10, 64); err == nil {
			startOffset = parsed
		}
	}

	var n int64
	if s.attachmentStore != nil {
		// Refuse to overwrite an existing object, but only on the initial
		// chunk (Upload-Offset == 0) so a legitimately resumed upload at a
		// non-zero offset is not rejected.
		if startOffset == 0 {
			if exists, err := s.attachmentStore.Exists(r.Context(), key); err != nil {
				s.logger.Error("attachment exists check failed", "key", key, "error", err.Error())
				writeError(w, http.StatusInternalServerError, "upload failed")
				return
			} else if exists {
				writeError(w, http.StatusConflict, "attachment already exists")
				return
			}
		}
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
	if !isSafeCDNKey(key) {
		writeError(w, http.StatusBadRequest, "invalid attachment key")
		return
	}

	if s.attachmentStore != nil {
		// Refuse to overwrite an existing object so a caller cannot clobber
		// another upload's content at a known key.
		if exists, err := s.attachmentStore.Exists(r.Context(), key); err != nil {
			s.logger.Error("attachment exists check failed", "key", key, "error", err.Error())
			writeError(w, http.StatusInternalServerError, "upload failed")
			return
		} else if exists {
			writeError(w, http.StatusConflict, "attachment already exists")
			return
		}
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
	if !isSafeCDNKey(key) {
		writeError(w, http.StatusBadRequest, "invalid attachment key")
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
	defer func() { _ = reader.Close() }()

	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, reader); err != nil {
		s.logger.Error("attachment download interrupted", "key", key, "error", err.Error())
	}
}
