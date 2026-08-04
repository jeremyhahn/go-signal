package signal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_FIDO2Capabilities_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/fido2/capabilities" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"webAuthn": true, "userVerification": "required"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	caps, err := c.FIDO2Capabilities(context.Background())
	if err != nil {
		t.Fatalf("FIDO2Capabilities: %v", err)
	}
	if caps["webAuthn"] != true {
		t.Errorf("caps = %v", caps)
	}
}

func TestClient_FIDO2Capabilities_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.FIDO2Capabilities(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_FIDO2ListCredentials_Success(t *testing.T) {
	creds := []FIDO2Credential{
		{CredentialID: "cred-1", Name: "YubiKey"},
		{CredentialID: "cred-2", Name: "TouchID"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/fido2/credentials" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"credentials": creds})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	got, err := c.FIDO2ListCredentials(context.Background())
	if err != nil {
		t.Fatalf("FIDO2ListCredentials: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(got))
	}
}

func TestClient_FIDO2ListCredentials_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.FIDO2ListCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_FIDO2DeleteCredential_Success(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.FIDO2DeleteCredential(context.Background(), "cred-abc"); err != nil {
		t.Fatalf("FIDO2DeleteCredential: %v", err)
	}
	if gotPath != "/v1/fido2/credentials/cred-abc" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestClient_FIDO2DeleteCredential_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.FIDO2DeleteCredential(context.Background(), "bad-id"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_FIDO2RenameCredential_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %q", r.Method)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "MyKey" {
			t.Errorf("body name = %q", body["name"])
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.FIDO2RenameCredential(context.Background(), "cred-1", "MyKey"); err != nil {
		t.Fatalf("FIDO2RenameCredential: %v", err)
	}
}

func TestClient_FIDO2RenameCredential_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.FIDO2RenameCredential(context.Background(), "bad", "name"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_FIDO2RegisterKey_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/fido2/session" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"challenge": "base64abc"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	opts, err := c.FIDO2RegisterKey(context.Background(), "alice")
	if err != nil {
		t.Fatalf("FIDO2RegisterKey: %v", err)
	}
	if opts["challenge"] == nil {
		t.Error("expected challenge in response")
	}
}

func TestClient_FIDO2RegisterKey_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.FIDO2RegisterKey(context.Background(), "alice")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_FIDO2FinishRegistration_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/fido2/register/complete" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	err := c.FIDO2FinishRegistration(context.Background(), "sess-id", map[string]any{"id": "cred-bytes"})
	if err != nil {
		t.Fatalf("FIDO2FinishRegistration: %v", err)
	}
}

func TestClient_FIDO2BeginLogin_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/fido2/login/begin" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"challenge": "xyz"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	opts, err := c.FIDO2BeginLogin(context.Background())
	if err != nil {
		t.Fatalf("FIDO2BeginLogin: %v", err)
	}
	if opts["challenge"] == nil {
		t.Error("expected challenge in response")
	}
}

func TestClient_FIDO2BeginLogin_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.FIDO2BeginLogin(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_FIDO2FinishLogin_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/fido2/login/complete" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	err := c.FIDO2FinishLogin(context.Background(), map[string]any{"id": "cred", "response": "data"})
	if err != nil {
		t.Fatalf("FIDO2FinishLogin: %v", err)
	}
}

func TestClient_FIDO2FinishLogin_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.FIDO2FinishLogin(context.Background(), map[string]any{"id": "bad"}); err == nil {
		t.Fatal("expected error")
	}
}
