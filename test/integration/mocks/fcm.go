//go:build integration

package mocks

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// FCMMock fakes the OAuth2 token endpoint and FCM v1 send, with a fixed access token; SetNextSendResponse overrides the next send.
type FCMMock struct {
	Server *httptest.Server

	mu             sync.Mutex
	tokensIssued   int
	sendsReceived  int
	lastSendBody   []byte
	lastSendAuth   string
	nextSendStatus int
	nextSendBody   string
	accessToken    string
}

// NewFCMMock returns a started mock server.
func NewFCMMock() *FCMMock {
	m := &FCMMock{accessToken: "mock-access-token"}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/v1/", m.handleSend)
	m.Server = httptest.NewServer(mux)
	return m
}

// Close shuts the underlying httptest.Server down.
func (m *FCMMock) Close() { m.Server.Close() }

// TokenURL returns the OAuth2 token-grant endpoint URL (pass as
// fcm.Config.TokenEndpoint).
func (m *FCMMock) TokenURL() string { return m.Server.URL + "/token" }

// SendURL returns the FCM v1 send endpoint URL for the supplied project
// (pass as fcm.Config.SendEndpoint).
func (m *FCMMock) SendURL(projectID string) string {
	return m.Server.URL + "/v1/projects/" + projectID + "/messages:send"
}

// TokensIssued returns the number of /token grants the mock has served.
// Tests use this to assert OAuth2 caching is working.
func (m *FCMMock) TokensIssued() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokensIssued
}

// SendsReceived returns the number of /messages:send calls the mock
// has accepted.
func (m *FCMMock) SendsReceived() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sendsReceived
}

// LastSend returns the most recent send call's Authorization header
// value + JSON body. Tests assert on both — Authorization should carry
// "Bearer mock-access-token", body should embed the device token and
// the per-NotificationType data key.
func (m *FCMMock) LastSend() (authHeader string, body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastSendAuth, append([]byte(nil), m.lastSendBody...)
}

// SetNextSendResponse makes the next send return status and body.
func (m *FCMMock) SetNextSendResponse(status int, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextSendStatus = status
	m.nextSendBody = body
}

func (m *FCMMock) handleToken(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.tokensIssued++
	tok := m.accessToken
	m.mu.Unlock()

	// Quick sanity: real Google rejects non-POST. Mirror that so tests
	// catch a buggy provider that mis-formed the request.
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	resp, _ := json.Marshal(map[string]any{
		"access_token": tok,
		"expires_in":   3600,
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

func (m *FCMMock) handleSend(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/messages:send") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	body, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	m.sendsReceived++
	m.lastSendBody = append([]byte(nil), body...)
	m.lastSendAuth = r.Header.Get("Authorization")
	status := m.nextSendStatus
	overrideBody := m.nextSendBody
	m.nextSendStatus = 0
	m.nextSendBody = ""
	m.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(overrideBody))
		return
	}
	resp, _ := json.Marshal(map[string]string{"name": "projects/p/messages/m1"})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}
