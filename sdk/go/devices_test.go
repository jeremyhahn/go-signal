package signal

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClient_ListDevices_Success(t *testing.T) {
	devices := []Device{
		{ID: 1, Name: "primary", Created: time.Now(), LastSeen: time.Now()},
		{ID: 2, Name: "tablet", Created: time.Now(), LastSeen: time.Now()},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/devices" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"devices": devices})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	got, err := c.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(got))
	}
	if got[0].ID != 1 {
		t.Errorf("devices[0].ID = %d", got[0].ID)
	}
}

func TestClient_ListDevices_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.ListDevices(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_RemoveDevice_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/3") {
			t.Errorf("path = %q, expected to end with /3", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.RemoveDevice(context.Background(), 3); err != nil {
		t.Fatalf("RemoveDevice: %v", err)
	}
}

func TestClient_RemoveDevice_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.RemoveDevice(context.Background(), 99); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_AddDevice_Success(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodPut {
			t.Errorf("method = %q", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	// Use a simple token without query params so r.URL.Path matches exactly.
	uri := "linkdevice-token-abc123"
	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.AddDevice(context.Background(), uri); err != nil {
		t.Fatalf("AddDevice: %v", err)
	}
	want := fmt.Sprintf("/v1/provisioning/%s", uri)
	if gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

func TestClient_AddDevice_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.AddDevice(context.Background(), "bad-uri"); err == nil {
		t.Fatal("expected error")
	}
}
