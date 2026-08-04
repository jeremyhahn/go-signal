package signal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func TestDoRequest_GetSuccess(t *testing.T) {
	type resp struct{ Value string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/test" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp{Value: "hello"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	var out resp
	err := c.doRequest(context.Background(), http.MethodGet, "/v1/test", nil, &out)
	if err != nil {
		t.Fatalf("doRequest: %v", err)
	}
	if out.Value != "hello" {
		t.Errorf("out.Value = %q", out.Value)
	}
}

func TestDoRequest_WithBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing Content-Type: application/json")
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["key"] != "val" {
			t.Errorf("body = %v", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	err := c.doRequest(context.Background(), http.MethodPost, "/v1/test", map[string]string{"key": "val"}, nil)
	if err != nil {
		t.Fatalf("doRequest with body: %v", err)
	}
}

func TestDoRequest_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	err := c.doRequest(context.Background(), http.MethodGet, "/v1/test", nil, nil)
	if err == nil {
		t.Fatal("expected error for 5xx response")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d", apiErr.StatusCode)
	}
}

func TestDoRequest_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-valid-json"))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	var out struct{ V int }
	err := c.doRequest(context.Background(), http.MethodGet, "/v1/test", nil, &out)
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestDoRequest_NoContentResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	var out struct{ V int }
	// result is non-nil but status is 204 — decode should be skipped.
	err := c.doRequest(context.Background(), http.MethodGet, "/v1/test", nil, &out)
	if err != nil {
		t.Fatalf("doRequest 204: %v", err)
	}
}

func TestDoRequest_WithBasicAuth_UsingUUID(t *testing.T) {
	creds := &Credentials{
		UUID:     "user-uuid",
		DeviceID: 1,
		Password: secrets.NewSecureString("mypass"),
	}
	ms := &mockStore{credentials: creds}

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := ClientConfig{
		ServerURL: srv.URL,
		DataDir:   t.TempDir(),
		Store:     ms,
		Password:  secrets.NewSecureString("mypass"),
		DeviceID:  1,
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	_ = c.doRequest(context.Background(), http.MethodGet, "/v1/test", nil, nil)
	if gotAuth == "" {
		t.Error("expected Authorization header to be set")
	}
}

func TestDoRequest_WithBasicAuth_FallbackToAccount(t *testing.T) {
	// No UUID in store, falls back to config.Account.
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	cfg := ClientConfig{
		ServerURL: srv.URL,
		DataDir:   t.TempDir(),
		Store:     &stubStore{}, // GetCredentials returns nil
		Account:   "+15550000001",
		Password:  secrets.NewSecureString("pw"),
		DeviceID:  1,
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	_ = c.doRequest(context.Background(), http.MethodGet, "/v1/test", nil, nil)
	if gotAuth == "" {
		t.Error("expected Authorization header")
	}
}

func TestDoRequestWithAuth_Success(t *testing.T) {
	type result struct{ OK bool }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "testuser" || pass != "testpass" {
			t.Errorf("auth mismatch: user=%q pass=%q ok=%v", user, pass, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result{OK: true})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	var out result
	err := c.doRequestWithAuth(context.Background(), http.MethodPost, "/v1/test",
		"testuser", "testpass", nil, &out)
	if err != nil {
		t.Fatalf("doRequestWithAuth: %v", err)
	}
	if !out.OK {
		t.Error("expected OK=true in response")
	}
}

func TestDoRequestWithAuth_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	err := c.doRequestWithAuth(context.Background(), http.MethodPost, "/v1/test",
		"u", "p", nil, nil)
	if err == nil {
		t.Fatal("expected error for 403")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d", apiErr.StatusCode)
	}
}

func TestDoRequestWithAuth_DecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-valid-json"))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	var out struct{ V int }
	err := c.doRequestWithAuth(context.Background(), http.MethodGet, "/v1/test",
		"u", "p", nil, &out)
	if err == nil {
		t.Fatal("expected decode error from malformed JSON")
	}
}

func TestDoRequestWithAuth_WithBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["ping"] != "pong" {
			t.Errorf("body = %v", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	err := c.doRequestWithAuth(context.Background(), http.MethodPost, "/v1/test",
		"u", "p", map[string]string{"ping": "pong"}, nil)
	if err != nil {
		t.Fatalf("doRequestWithAuth with body: %v", err)
	}
}
