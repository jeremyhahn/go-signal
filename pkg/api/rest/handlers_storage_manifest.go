package rest

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	"github.com/jeremyhahn/go-signal/pkg/securestorage/storagepb"
)

// storageContentType is the protobuf media type Signal storage clients use.
const storageContentType = "application/x-protobuf"

// maxStorageBodyBytes bounds a storage write/read request body.
const maxStorageBodyBytes = 8 * 1024 * 1024

// handleGetStorageManifestVersion is the entry point for all storage-service
// requests. When no manifest store is configured it returns 204 (the safe
// "nothing to sync" stub, used when an external storage-service is wired).
// When a store IS configured it serves the real Signal storage protocol:
// manifest fetch, write operations, and reads.
//
// The protocol is validated against the canonical Signal client library
// (libsignal-service-java): the StorageService.proto message field numbers and
// the PushServiceSocket paths/methods match exactly —
//   - GET  /v1/storage/manifest                    → current manifest
//   - GET  /v1/storage/manifest/version/{version}  → manifest if newer, else 204
//   - PUT  /v1/storage                             → WriteOperation
//   - PUT  /v1/storage/read                        → ReadOperation → StorageItems
//
// Routing: the registered routes funnel manifest GETs, write PUTs, and read
// PUTs here; this handler dispatches on method and path. All routes are wrapped
// with account auth, so the authenticated account UUID scopes every operation.
func (s *Server) handleGetStorageManifestVersion(w http.ResponseWriter, r *http.Request) {
	if s.secureStorage == nil || !s.secureStorage.StorageEnabled() {
		// Storage-service disabled: report nothing to sync.
		w.WriteHeader(http.StatusNoContent)
		return
	}

	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && strings.Contains(path, "manifest"):
		s.handleStorageGetManifest(w, r, acct.UUID)
	case r.Method == http.MethodPut && strings.HasSuffix(path, "/read"):
		s.handleStorageRead(w, r, acct.UUID)
	case r.Method == http.MethodPut:
		s.handleStorageWrite(w, r, acct.UUID)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleStorageGetManifest serves GET .../manifest and
// GET .../manifest/version/{version}. The latter returns the current manifest
// only when it is newer than the client's version; otherwise 204.
func (s *Server) handleStorageGetManifest(w http.ResponseWriter, r *http.Request, accountUUID string) {
	manifest, err := s.secureStorage.GetManifest(r.Context(), accountUUID)
	if err != nil {
		s.logger.Error("failed to get storage manifest", "uuid", accountUUID, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "failed to read manifest")
		return
	}
	if manifest == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// If the client supplied a version, only return the manifest when ours is
	// strictly newer (matching Signal's conditional manifest fetch).
	if v := r.PathValue("version"); v != "" {
		if clientVersion, perr := strconv.ParseUint(v, 10, 64); perr == nil && manifest.Version <= clientVersion {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	writeStorageProto(w, s, accountUUID, &storagepb.StorageManifest{
		Version: manifest.Version,
		Value:   manifest.Value,
	})
}

// handleStorageWrite applies a WriteOperation. On a version conflict it returns
// 409 with the current manifest, matching Signal's optimistic-concurrency
// contract.
func (s *Server) handleStorageWrite(w http.ResponseWriter, r *http.Request, accountUUID string) {
	body, ok := readStorageBody(w, r)
	if !ok {
		return
	}
	var op storagepb.WriteOperation
	if err := proto.Unmarshal(body, &op); err != nil {
		writeError(w, http.StatusBadRequest, "invalid write operation")
		return
	}
	if op.Manifest == nil {
		writeError(w, http.StatusBadRequest, "write operation requires a manifest")
		return
	}

	inserts := make([]*securestorage.StorageItem, 0, len(op.InsertItem))
	for _, it := range op.InsertItem {
		inserts = append(inserts, &securestorage.StorageItem{Key: it.Key, Value: it.Value})
	}

	conflict, err := s.secureStorage.Write(
		r.Context(),
		accountUUID,
		&securestorage.StorageManifest{Version: op.Manifest.Version, Value: op.Manifest.Value},
		inserts,
		op.DeleteKey,
		op.ClearAll,
	)
	if err != nil {
		s.logger.Error("failed to apply storage write", "uuid", accountUUID, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "failed to apply write")
		return
	}
	if conflict != nil {
		// 409 with the current manifest so the client can rebase and retry.
		w.Header().Set("Content-Type", storageContentType)
		w.WriteHeader(http.StatusConflict)
		writeProtoBody(w, s, accountUUID, &storagepb.StorageManifest{
			Version: conflict.Version,
			Value:   conflict.Value,
		})
		return
	}
	w.WriteHeader(http.StatusOK)
}

// handleStorageRead serves a ReadOperation, returning the requested items.
func (s *Server) handleStorageRead(w http.ResponseWriter, r *http.Request, accountUUID string) {
	body, ok := readStorageBody(w, r)
	if !ok {
		return
	}
	var op storagepb.ReadOperation
	if err := proto.Unmarshal(body, &op); err != nil {
		writeError(w, http.StatusBadRequest, "invalid read operation")
		return
	}

	items, err := s.secureStorage.Read(r.Context(), accountUUID, op.ReadKey)
	if err != nil {
		s.logger.Error("failed to read storage items", "uuid", accountUUID, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "failed to read items")
		return
	}

	resp := &storagepb.StorageItems{Items: make([]*storagepb.StorageItem, 0, len(items))}
	for _, it := range items {
		resp.Items = append(resp.Items, &storagepb.StorageItem{Key: it.Key, Value: it.Value})
	}
	writeStorageProto(w, s, accountUUID, resp)
}

// readStorageBody reads a bounded request body, writing a 400 and returning
// false on failure.
func readStorageBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxStorageBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
		return nil, false
	}
	return body, true
}

// writeStorageProto marshals m and writes it with a 200 status and the
// protobuf content type.
func writeStorageProto(w http.ResponseWriter, s *Server, accountUUID string, m proto.Message) {
	w.Header().Set("Content-Type", storageContentType)
	w.WriteHeader(http.StatusOK)
	writeProtoBody(w, s, accountUUID, m)
}

// writeProtoBody marshals and writes m to an already-started response.
func writeProtoBody(w http.ResponseWriter, s *Server, accountUUID string, m proto.Message) {
	data, err := proto.Marshal(m)
	if err != nil {
		s.logger.Error("failed to marshal storage response", "uuid", accountUUID, "error", err.Error())
		return
	}
	if _, err := w.Write(data); err != nil {
		s.logger.Error("failed to write storage response", "uuid", accountUUID, "error", err.Error())
	}
}
