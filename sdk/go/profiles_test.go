package signal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_UpdateProfile_GivenNameOnly(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/profile" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	err := c.UpdateProfile(context.Background(), Profile{GivenName: "Alice"})
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if gotBody["name"] != "Alice" {
		t.Errorf("name = %v", gotBody["name"])
	}
}

func TestClient_UpdateProfile_FullName(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	err := c.UpdateProfile(context.Background(), Profile{GivenName: "Alice", FamilyName: "Smith"})
	if err != nil {
		t.Fatalf("UpdateProfile full name: %v", err)
	}
	// Name should be "Alice\x00Smith".
	name, _ := gotBody["name"].(string)
	if len(name) == 0 {
		t.Error("expected non-empty name in body")
	}
}

func TestClient_UpdateProfile_WithAbout(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	err := c.UpdateProfile(context.Background(), Profile{About: "Hello world", AboutEmoji: "👋"})
	if err != nil {
		t.Fatalf("UpdateProfile with about: %v", err)
	}
	if gotBody["about"] != "Hello world" {
		t.Errorf("about = %v", gotBody["about"])
	}
	if gotBody["aboutEmoji"] != "👋" {
		t.Errorf("aboutEmoji = %v", gotBody["aboutEmoji"])
	}
}

func TestClient_UpdateProfile_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.UpdateProfile(context.Background(), Profile{GivenName: "X"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_GetProfile_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/profile/user-uuid-123" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Profile{GivenName: "Bob", About: "Hey there"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	profile, err := c.GetProfile(context.Background(), "user-uuid-123")
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if profile.GivenName != "Bob" {
		t.Errorf("GivenName = %q", profile.GivenName)
	}
}

func TestClient_GetProfile_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.GetProfile(context.Background(), "bad-uuid")
	if err == nil {
		t.Fatal("expected error")
	}
}
