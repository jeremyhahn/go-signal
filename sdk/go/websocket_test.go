package signal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBasicAuth_Format(t *testing.T) {
	got := basicAuth("user", "pass")
	if !strings.HasPrefix(got, "Basic ") {
		t.Errorf("basicAuth = %q, expected prefix 'Basic '", got)
	}
	encoded := strings.TrimPrefix(got, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != "user:pass" {
		t.Errorf("decoded = %q", decoded)
	}
}

func TestBasicAuth_EmptyValues(t *testing.T) {
	got := basicAuth("", "")
	if !strings.HasPrefix(got, "Basic ") {
		t.Errorf("basicAuth empty = %q", got)
	}
}

func TestClient_ConnectWebSocket_NoCredentials(t *testing.T) {
	// Without credentials, ConnectWebSocket returns immediately with an error.
	c := newTestClient(t, "http://localhost", &stubStore{})
	err := c.ConnectWebSocket(context.Background(), func(_ ReceivedMessage) {})
	if err == nil {
		t.Fatal("expected error when no credentials")
	}
}

func TestClient_ReceiveWebSocket_DelegatesToReceive(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("ws message body"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/messages":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"messages": []ReceivedMessage{{
					Type:    8,
					Content: encoded,
					Source:  "sender",
				}},
				"more": false,
			})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	msgs, err := c.ReceiveWebSocket(context.Background(), 5*time.Second)
	if err != nil {
		t.Fatalf("ReceiveWebSocket: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
}

func TestConnectWebSocket_WithCredentials_HTTP(t *testing.T) {
	// Regular HTTP server (not WebSocket) — Dial will fail after scheme conversion.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	creds := &Credentials{UUID: "test-uuid", DeviceID: 1, Password: NewSecurePassword("pw")}
	ms := &mockStore{credentials: creds}
	c := newTestClient(t, srv.URL, ms) // srv.URL is "http://..."

	err := c.ConnectWebSocket(context.Background(), func(_ ReceivedMessage) {})
	if err == nil {
		t.Fatal("expected error: plain HTTP server cannot satisfy WebSocket upgrade")
	}
	if strings.Contains(err.Error(), "no credentials") {
		t.Errorf("got credentials error unexpectedly: %v", err)
	}
}

func TestConnectWebSocket_WithCredentials_HTTPS(t *testing.T) {
	// TLS server so the URL begins with "https://" — covers the https→wss branch.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	creds := &Credentials{UUID: "tls-uuid", DeviceID: 1}
	ms := &mockStore{credentials: creds}
	cfg := ClientConfig{
		ServerURL: srv.URL, // "https://..."
		DataDir:   t.TempDir(),
		Store:     ms,
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	// ConnectWebSocket converts https:// → wss:// then Dial fails (not a WS server).
	err = c.ConnectWebSocket(context.Background(), func(_ ReceivedMessage) {})
	if err == nil {
		t.Fatal("expected error from non-WebSocket TLS server")
	}
}

func TestConnectWebSocket_WithCACert(t *testing.T) {
	// Cover the CACert block inside ConnectWebSocket by injecting a SecureString
	// directly onto the client config (bypasses NewClient's strict PEM validation).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	creds := &Credentials{UUID: "cert-uuid", DeviceID: 1}
	ms := &mockStore{credentials: creds}
	c := newTestClient(t, srv.URL, ms)

	// ConnectWebSocket reads c.config.CACert; setting it here after NewClient
	// avoids the strict PEM validation in NewClient itself.
	c.config.CACert = NewSecurePassword("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----")
	defer c.config.CACert.Destroy()

	// Dial will fail (not a WS server); the CACert block still runs.
	_ = c.ConnectWebSocket(context.Background(), func(_ ReceivedMessage) {})
}

func TestClient_ReceiveWebSocket_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.ReceiveWebSocket(context.Background(), time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
}
