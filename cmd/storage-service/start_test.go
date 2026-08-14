package main

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
	"strings"
	"testing"

	memstorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

func newTestMux(t *testing.T, secret string) (*httptest.Server, *memstorage.MemoryManifestStore) {
	t.Helper()
	store := memstorage.NewMemoryManifestStore()
	mux := NewMux(store, []byte(secret), slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, store
}

func hmacAuthHeader(identity, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(identity))
	pw := hex.EncodeToString(mac.Sum(nil))
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(identity+":"+pw))
}

func do(t *testing.T, method, url, auth string, body []byte) *http.Response {
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

func TestStorageService_AuthRequired(t *testing.T) {
	srv, _ := newTestMux(t, "secret-1")
	resp := do(t, http.MethodGet, srv.URL+"/v1/storage/manifest", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	// Wrong HMAC password.
	resp = do(t, http.MethodGet, srv.URL+"/v1/storage/manifest",
		"Basic "+base64.StdEncoding.EncodeToString([]byte("alice:wrong")), nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 with bad password, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestStorageService_ManifestRoundTrip(t *testing.T) {
	srv, store := newTestMux(t, "secret-1")
	auth := hmacAuthHeader("alice", "secret-1")

	// PUT manifest.
	value := []byte("encrypted-manifest-blob")
	body, _ := json.Marshal(manifestJSON{Version: 1, Value: base64.StdEncoding.EncodeToString(value)})
	resp := do(t, http.MethodPut, srv.URL+"/v1/storage/manifest", auth, body)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("PUT manifest = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// GET manifest.
	resp = do(t, http.MethodGet, srv.URL+"/v1/storage/manifest", auth, nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET manifest = %d", resp.StatusCode)
	}
	var got manifestJSON
	_ = json.NewDecoder(resp.Body).Decode(&got)
	_ = resp.Body.Close()
	if got.Version != 1 {
		t.Errorf("Version = %d", got.Version)
	}
	gotValue, _ := base64.StdEncoding.DecodeString(got.Value)
	if !bytes.Equal(gotValue, value) {
		t.Errorf("value round-trip mismatch")
	}

	// Storage backend reflects the write.
	if m, err := store.GetManifest(context.Background(), "alice"); err != nil {
		t.Errorf("backend GetManifest: %v", err)
	} else if m.Version != 1 {
		t.Errorf("backend Version = %d", m.Version)
	}
}

func TestStorageService_ManifestVersionConflict(t *testing.T) {
	srv, _ := newTestMux(t, "s")
	auth := hmacAuthHeader("alice", "s")
	body, _ := json.Marshal(manifestJSON{Version: 5, Value: base64.StdEncoding.EncodeToString([]byte("v5"))})
	resp := do(t, http.MethodPut, srv.URL+"/v1/storage/manifest", auth, body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("first PUT = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	// Old version → 409.
	body, _ = json.Marshal(manifestJSON{Version: 3, Value: base64.StdEncoding.EncodeToString([]byte("v3"))})
	resp = do(t, http.MethodPut, srv.URL+"/v1/storage/manifest", auth, body)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 on version conflict, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestStorageService_ItemRoundTripAndDelete(t *testing.T) {
	srv, _ := newTestMux(t, "s")
	auth := hmacAuthHeader("alice", "s")
	rawKey := []byte("contacts:001")
	keyPath := base64.RawURLEncoding.EncodeToString(rawKey)

	// PUT item.
	body, _ := json.Marshal(itemJSON{
		Key:   base64.StdEncoding.EncodeToString(rawKey),
		Value: base64.StdEncoding.EncodeToString([]byte("encrypted-contact-001")),
	})
	resp := do(t, http.MethodPut, srv.URL+"/v1/storage/item/"+keyPath, auth, body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PUT item = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	// GET item.
	resp = do(t, http.MethodGet, srv.URL+"/v1/storage/item/"+keyPath, auth, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET item = %d", resp.StatusCode)
	}
	var got itemJSON
	_ = json.NewDecoder(resp.Body).Decode(&got)
	_ = resp.Body.Close()
	if v, _ := base64.StdEncoding.DecodeString(got.Value); string(v) != "encrypted-contact-001" {
		t.Errorf("item value round-trip mismatch: %q", v)
	}
	// DELETE item.
	resp = do(t, http.MethodDelete, srv.URL+"/v1/storage/item/"+keyPath, auth, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE item = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	// GET after delete → 404.
	resp = do(t, http.MethodGet, srv.URL+"/v1/storage/item/"+keyPath, auth, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 after delete, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestStorageService_DeleteAllPurgesAccount(t *testing.T) {
	srv, store := newTestMux(t, "s")
	auth := hmacAuthHeader("alice", "s")
	// Seed manifest + item.
	body, _ := json.Marshal(manifestJSON{Version: 1, Value: base64.StdEncoding.EncodeToString([]byte("m"))})
	_ = do(t, http.MethodPut, srv.URL+"/v1/storage/manifest", auth, body).Body.Close()
	keyPath := base64.RawURLEncoding.EncodeToString([]byte("k"))
	body, _ = json.Marshal(itemJSON{Key: base64.StdEncoding.EncodeToString([]byte("k")), Value: ""})
	_ = do(t, http.MethodPut, srv.URL+"/v1/storage/item/"+keyPath, auth, body).Body.Close()

	// DELETE /v1/storage purges.
	resp := do(t, http.MethodDelete, srv.URL+"/v1/storage", auth, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE /v1/storage = %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	if _, err := store.GetManifest(context.Background(), "alice"); err == nil {
		t.Error("manifest should be gone after DeleteAll")
	}
}

func TestStorageService_GetMissingManifestReturns404(t *testing.T) {
	srv, _ := newTestMux(t, "s")
	auth := hmacAuthHeader("alice", "s")
	resp := do(t, http.MethodGet, srv.URL+"/v1/storage/manifest", auth, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestStorageService_InvalidBase64Rejected(t *testing.T) {
	srv, _ := newTestMux(t, "s")
	auth := hmacAuthHeader("alice", "s")
	body := []byte(`{"version":1,"value":"!!!"}`)
	resp := do(t, http.MethodPut, srv.URL+"/v1/storage/manifest", auth, body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for bad base64, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

func TestStorageService_DeleteItem_IdempotentOnMissing(t *testing.T) {
	srv, _ := newTestMux(t, "s")
	auth := hmacAuthHeader("alice", "s")
	keyPath := base64.RawURLEncoding.EncodeToString([]byte("never-existed"))
	resp := do(t, http.MethodDelete, srv.URL+"/v1/storage/item/"+keyPath, auth, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE missing item should be 204, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

// helpers to silence unused-import lint when adding tests incrementally.
var _ = strings.HasPrefix
