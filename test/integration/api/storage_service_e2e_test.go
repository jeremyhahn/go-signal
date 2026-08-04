//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/extservice/storage"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	memstorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

// startStorageServiceInProcess mounts the storage-service mux on an
// httptest.NewServer. Returns the server URL and the backing store
// for direct assertions.
//
// We duplicate the NewMux setup here rather than importing
// cmd/storage-service's `main` package: Go disallows that.
func startStorageServiceInProcess(t *testing.T, sharedSecret string) (*httptest.Server, *memstorage.MemoryManifestStore) {
	t.Helper()
	store := memstorage.NewMemoryManifestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mux := buildStorageMux(store, []byte(sharedSecret), logger)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, store
}

// buildStorageMux mirrors cmd/storage-service's NewMux for the e2e
// test. Cross-package re-use of main-binary handlers is not directly
// supported; the wiring is small and stays in sync via the shared
// pkg/securestorage.ManifestStore interface.
func buildStorageMux(store securestorage.ManifestStore, secret []byte, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /v1/storage/manifest", basicAuthMW(secret, getManifestE2E(store)))
	mux.Handle("PUT /v1/storage/manifest", basicAuthMW(secret, putManifestE2E(store)))
	mux.Handle("GET /v1/storage/item/{key}", basicAuthMW(secret, getItemE2E(store)))
	mux.Handle("PUT /v1/storage/item/{key}", basicAuthMW(secret, putItemE2E(store)))
	mux.Handle("DELETE /v1/storage/item/{key}", basicAuthMW(secret, deleteItemE2E(store)))
	mux.Handle("DELETE /v1/storage", basicAuthMW(secret, deleteAllE2E(store, logger)))
	return mux
}

type e2eIdentityCtxKey struct{}

func basicAuthMW(secret []byte, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if len(hdr) < 6 || hdr[:6] != "Basic " {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(hdr[6:])
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sep := -1
		for i, b := range raw {
			if b == ':' {
				sep = i
				break
			}
		}
		if sep < 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		user := string(raw[:sep])
		pass := string(raw[sep+1:])
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(user))
		if pass != hex.EncodeToString(mac.Sum(nil)) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), e2eIdentityCtxKey{}, user)))
	})
}

func identityE2E(r *http.Request) string {
	if v, ok := r.Context().Value(e2eIdentityCtxKey{}).(string); ok {
		return v
	}
	return ""
}

type manifestPayload struct {
	Version uint64 `json:"version"`
	Value   string `json:"value"`
}

type itemPayload struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func getManifestE2E(store securestorage.ManifestStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m, err := store.GetManifest(r.Context(), identityE2E(r))
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(manifestPayload{Version: m.Version, Value: base64.StdEncoding.EncodeToString(m.Value)})
	}
}

func putManifestE2E(store securestorage.ManifestStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req manifestPayload
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		value, err := base64.StdEncoding.DecodeString(req.Value)
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		if err := store.PutManifest(r.Context(), identityE2E(r), &securestorage.StorageManifest{
			Version: req.Version, Value: value,
		}); err != nil {
			http.Error(w, "internal", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func getItemE2E(store securestorage.ManifestStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, err := base64.RawURLEncoding.DecodeString(r.PathValue("key"))
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		it, err := store.GetItem(r.Context(), identityE2E(r), key)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(itemPayload{
			Key:   base64.StdEncoding.EncodeToString(it.Key),
			Value: base64.StdEncoding.EncodeToString(it.Value),
		})
	}
}

func putItemE2E(store securestorage.ManifestStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, err := base64.RawURLEncoding.DecodeString(r.PathValue("key"))
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		var req itemPayload
		_ = json.NewDecoder(r.Body).Decode(&req)
		value, _ := base64.StdEncoding.DecodeString(req.Value)
		_ = store.PutItem(r.Context(), identityE2E(r), &securestorage.StorageItem{Key: key, Value: value})
		w.WriteHeader(http.StatusNoContent)
	}
}

func deleteItemE2E(store securestorage.ManifestStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, err := base64.RawURLEncoding.DecodeString(r.PathValue("key"))
		if err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_ = store.DeleteItem(r.Context(), identityE2E(r), key)
		w.WriteHeader(http.StatusNoContent)
	}
}

func deleteAllE2E(store securestorage.ManifestStore, _ *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = store.DeleteAll(r.Context(), identityE2E(r))
		w.WriteHeader(http.StatusNoContent)
	}
}

// TestStorageServiceE2E_AdminDeleteViaSignaldClient drives the
// chat-server-to-storage-service admin path. signald's
// extservice/storage.HTTPClient calls DELETE /v1/storage; the
// per-account manifest + items disappear.
func TestStorageServiceE2E_AdminDeleteViaSignaldClient(t *testing.T) {
	const sharedSecret = "phase-4-4-secret"
	srv, store := startStorageServiceInProcess(t, sharedSecret)
	ctx := context.Background()

	// Seed two accounts so we can confirm only alice is purged.
	_ = store.PutManifest(ctx, "alice", &securestorage.StorageManifest{Version: 1, Value: []byte("alice-manifest")})
	_ = store.PutItem(ctx, "alice", &securestorage.StorageItem{Key: []byte("k"), Value: []byte("v")})
	_ = store.PutManifest(ctx, "bob", &securestorage.StorageManifest{Version: 1, Value: []byte("bob-manifest")})

	cli, err := storage.NewHTTP(storage.HTTPConfig{
		BaseURL:      srv.URL,
		SharedSecret: sharedSecret,
		Timeout:      2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })

	if err := cli.DeleteStoredData(ctx, "alice"); err != nil {
		t.Fatalf("DeleteStoredData(alice): %v", err)
	}

	if _, err := store.GetManifest(ctx, "alice"); err == nil {
		t.Error("alice manifest should be gone")
	}
	if _, err := store.GetManifest(ctx, "bob"); err != nil {
		t.Errorf("bob manifest should remain: %v", err)
	}
}

// TestStorageServiceE2E_FullMobileClientFlow exercises the same
// HTTP surface a mobile client would hit:
//
//  1. PUT manifest
//  2. PUT item
//  3. GET item
//  4. DELETE item
//  5. GET item (404)
func TestStorageServiceE2E_FullMobileClientFlow(t *testing.T) {
	const sharedSecret = "mobile-client-flow-secret"
	srv, _ := startStorageServiceInProcess(t, sharedSecret)
	auth := hmacAuthHeaderE2E("alice", sharedSecret)

	body, _ := json.Marshal(manifestPayload{Version: 1, Value: base64.StdEncoding.EncodeToString([]byte("manifest"))})
	if resp := doRequest(t, http.MethodPut, srv.URL+"/v1/storage/manifest", auth, body); resp.StatusCode != http.StatusNoContent {
		t.Errorf("PUT manifest = %d", resp.StatusCode)
	}

	keyPath := base64.RawURLEncoding.EncodeToString([]byte("contacts:001"))
	body, _ = json.Marshal(itemPayload{Value: base64.StdEncoding.EncodeToString([]byte("ct-001"))})
	if resp := doRequest(t, http.MethodPut, srv.URL+"/v1/storage/item/"+keyPath, auth, body); resp.StatusCode != http.StatusNoContent {
		t.Errorf("PUT item = %d", resp.StatusCode)
	}

	resp := doRequest(t, http.MethodGet, srv.URL+"/v1/storage/item/"+keyPath, auth, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET item = %d", resp.StatusCode)
	}
	var got itemPayload
	_ = json.NewDecoder(resp.Body).Decode(&got)
	_ = resp.Body.Close()
	if v, _ := base64.StdEncoding.DecodeString(got.Value); string(v) != "ct-001" {
		t.Errorf("item value mismatch: %q", v)
	}

	if resp := doRequest(t, http.MethodDelete, srv.URL+"/v1/storage/item/"+keyPath, auth, nil); resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE item = %d", resp.StatusCode)
	}
	if resp := doRequest(t, http.MethodGet, srv.URL+"/v1/storage/item/"+keyPath, auth, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 after delete; got %d", resp.StatusCode)
	}
}

func hmacAuthHeaderE2E(identity, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(identity))
	pw := hex.EncodeToString(mac.Sum(nil))
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(identity+":"+pw))
}

func doRequest(t *testing.T, method, url, auth string, body []byte) *http.Response {
	t.Helper()
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, reqBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do %s: %v", url, err)
	}
	return resp
}
