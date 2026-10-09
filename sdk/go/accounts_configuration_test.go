package signal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- UpdateConfiguration ---

func TestClient_UpdateConfiguration_ReadReceipts(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.HasSuffix(r.URL.Path, "/attributes/") {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	v := true
	err := c.UpdateConfiguration(context.Background(), AccountConfiguration{ReadReceipts: &v})
	if err != nil {
		t.Fatalf("UpdateConfiguration: %v", err)
	}
	if got, ok := gotBody["readReceipts"].(bool); !ok || !got {
		t.Errorf("readReceipts = %v, want true", gotBody["readReceipts"])
	}
	if _, exists := gotBody["typingIndicators"]; exists {
		t.Error("typingIndicators should not be present when nil")
	}
}

func TestClient_UpdateConfiguration_AllFields(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	rr, ti, lp := false, true, false
	err := c.UpdateConfiguration(context.Background(), AccountConfiguration{
		ReadReceipts:     &rr,
		TypingIndicators: &ti,
		LinkPreviews:     &lp,
	})
	if err != nil {
		t.Fatalf("UpdateConfiguration: %v", err)
	}
	if got, ok := gotBody["readReceipts"].(bool); !ok || got {
		t.Errorf("readReceipts = %v, want false", gotBody["readReceipts"])
	}
	if got, ok := gotBody["typingIndicators"].(bool); !ok || !got {
		t.Errorf("typingIndicators = %v, want true", gotBody["typingIndicators"])
	}
	if got, ok := gotBody["linkPreviews"].(bool); !ok || got {
		t.Errorf("linkPreviews = %v, want false", gotBody["linkPreviews"])
	}
}

func TestClient_UpdateConfiguration_EmptyConfig(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	// All nil — sends an empty JSON object; server ignores.
	if err := c.UpdateConfiguration(context.Background(), AccountConfiguration{}); err != nil {
		t.Fatalf("UpdateConfiguration empty: %v", err)
	}
	if len(gotBody) != 0 {
		t.Errorf("expected empty body, got %v", gotBody)
	}
}

func TestClient_UpdateConfiguration_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	v := true
	err := c.UpdateConfiguration(context.Background(), AccountConfiguration{ReadReceipts: &v})
	if err == nil {
		t.Fatal("expected error on server failure")
	}
}

// --- DeleteLocalData ---

func TestClient_DeleteLocalData_RemovesDirectory(t *testing.T) {
	dir := t.TempDir()
	// Write a file into the directory so it's non-empty.
	p := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(p, []byte(`{"number":"+1"}`), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   dir,
		Store:     &stubStore{},
	}
	c, err := NewClient(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.DeleteLocalData(); err != nil {
		t.Fatalf("DeleteLocalData: %v", err)
	}

	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Error("data directory should have been removed")
	}
}

func TestClient_DeleteLocalData_AlreadyAbsent(t *testing.T) {
	// DataDir that does not exist — RemoveAll is a no-op, should not error.
	nonExistent := filepath.Join(t.TempDir(), "does-not-exist")
	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   nonExistent,
		Store:     &stubStore{},
	}
	c, err := NewClient(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.DeleteLocalData(); err != nil {
		t.Fatalf("DeleteLocalData on absent dir: %v", err)
	}
}

func TestClient_DeleteLocalData_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   dir,
		Store:     &stubStore{},
	}
	c, err := NewClient(t.Context(), cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if err := c.DeleteLocalData(); err != nil {
		t.Fatalf("DeleteLocalData empty dir: %v", err)
	}
	if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
		t.Error("empty directory should have been removed")
	}
}
