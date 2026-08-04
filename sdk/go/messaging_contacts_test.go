package signal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- SendContacts ---

func TestClient_SendContacts_Success(t *testing.T) {
	uuid := "self-uuid-123"
	creds := &Credentials{UUID: uuid, Number: "+15550000001", DeviceID: 1}
	contacts := []Contact{
		{Number: "+15550000002", Name: "Alice"},
		{Number: "+15550000003", Name: "Bob"},
	}

	var gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.Method != http.MethodPut {
			t.Errorf("method = %q, want PUT", r.Method)
		}
		// Decode the outer envelope.
		var envelope struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Errorf("decode envelope: %v", err)
		}
		if len(envelope.Messages) > 0 {
			data, _ := base64.StdEncoding.DecodeString(envelope.Messages[0].Content)
			_ = json.Unmarshal(data, &gotBody)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ms := &mockStore{credentials: creds, contacts: contacts}
	c := newTestClient(t, srv.URL, ms)

	if err := c.SendContacts(context.Background()); err != nil {
		t.Fatalf("SendContacts: %v", err)
	}
	if want := "/v1/messages/" + uuid; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	syncMsg, ok := gotBody["syncMessage"].(map[string]any)
	if !ok {
		t.Fatalf("syncMessage not present in body: %v", gotBody)
	}
	if _, ok := syncMsg["contacts"]; !ok {
		t.Error("syncMessage.contacts not present")
	}
}

func TestClient_SendContacts_EmptyContacts(t *testing.T) {
	uuid := "self-uuid-empty"
	creds := &Credentials{UUID: uuid, Number: "+15550000001", DeviceID: 1}

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	// No contacts in the store.
	ms := &mockStore{credentials: creds}
	c := newTestClient(t, srv.URL, ms)

	if err := c.SendContacts(context.Background()); err != nil {
		t.Fatalf("SendContacts with empty contacts: %v", err)
	}
	if !strings.HasSuffix(gotPath, uuid) {
		t.Errorf("path = %q, expected suffix %q", gotPath, uuid)
	}
}

func TestClient_SendContacts_NoCredentials(t *testing.T) {
	// stubStore returns nil credentials.
	c := newTestClient(t, "http://localhost", &stubStore{})
	err := c.SendContacts(context.Background())
	if err == nil {
		t.Fatal("expected error when no credentials")
	}
	if _, ok := err.(*NotRegisteredError); !ok {
		t.Errorf("expected *NotRegisteredError, got %T: %v", err, err)
	}
}

func TestClient_SendContacts_CredentialsNoUUID(t *testing.T) {
	// Credentials exist but UUID is empty — still should fail.
	creds := &Credentials{Number: "+15550000001", DeviceID: 1}
	ms := &mockStore{credentials: creds}
	c := newTestClient(t, "http://localhost", ms)
	err := c.SendContacts(context.Background())
	if err == nil {
		t.Fatal("expected error when UUID is empty")
	}
}

func TestClient_SendContacts_GetContactsError(t *testing.T) {
	creds := &Credentials{UUID: "some-uuid", Number: "+15550000001", DeviceID: 1}
	ms := &mockStore{credentials: creds, contactErr: errors.New("disk read error")}
	c := newTestClient(t, "http://localhost", ms)
	if err := c.SendContacts(context.Background()); err == nil {
		t.Fatal("expected error when GetContacts fails")
	}
}

func TestClient_SendContacts_ServerError(t *testing.T) {
	uuid := "self-uuid-err"
	creds := &Credentials{UUID: uuid, Number: "+15550000001", DeviceID: 1}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ms := &mockStore{credentials: creds}
	c := newTestClient(t, srv.URL, ms)

	if err := c.SendContacts(context.Background()); err == nil {
		t.Fatal("expected error on server failure")
	}
}
