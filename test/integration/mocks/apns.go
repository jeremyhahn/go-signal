//go:build integration

package mocks

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// APNsMock is a fake Apple Push Notification HTTP/2 server. Real APNs
// requires HTTP/2 + ALPN; the httptest.Server is HTTP/1.1, which is
// fine because go-signal connects through `github.com/sideshow/apns2`
// whose Host field accepts any URL — we just need to accept POSTs at
// `/3/device/{token}` and respond with APNs-shaped status + headers.
type APNsMock struct {
	Server *httptest.Server

	mu              sync.Mutex
	pushesReceived  int
	lastTokenInPath string
	lastTopic       string
	lastPushType    string
	lastPriority    string
	lastCollapseID  string
	lastBody        []byte
	nextStatus      int
	nextReason      string
	nextTimestamp   int64
}

// NewAPNsMock returns a started mock server.
func NewAPNsMock() *APNsMock {
	m := &APNsMock{}
	mux := http.NewServeMux()
	mux.HandleFunc("/3/device/", m.handlePush)
	m.Server = httptest.NewServer(mux)
	return m
}

// Close shuts the underlying httptest.Server down.
func (m *APNsMock) Close() { m.Server.Close() }

// URL returns the mock's base URL. Pass it to apns2.Client.Host or to
// our APNsProvider via a custom build path; the mock accepts any HTTP
// method/scheme.
func (m *APNsMock) URL() string { return m.Server.URL }

// PushesReceived returns the number of /3/device/{token} POSTs the
// mock has accepted.
func (m *APNsMock) PushesReceived() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pushesReceived
}

// LastPush returns the most recent push call's headers + body. Tests
// assert apns-topic + apns-priority + apns-push-type + collapse-id +
// the deviceToken slot of the path.
func (m *APNsMock) LastPush() (deviceToken, topic, pushType, priority, collapseID string, body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastTokenInPath, m.lastTopic, m.lastPushType, m.lastPriority, m.lastCollapseID, append([]byte(nil), m.lastBody...)
}

// SetNextResponse forces the next push call to respond with the
// supplied status and APNs error reason. status=410 + reason="Unregistered"
// drives the unregistered-token cleanup path in the production client.
func (m *APNsMock) SetNextResponse(status int, reason string, timestampMillis int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextStatus = status
	m.nextReason = reason
	m.nextTimestamp = timestampMillis
}

func (m *APNsMock) handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	// Path is /3/device/<token>.
	token := strings.TrimPrefix(r.URL.Path, "/3/device/")
	m.mu.Lock()
	m.pushesReceived++
	m.lastTokenInPath = token
	m.lastTopic = r.Header.Get("apns-topic")
	m.lastPushType = r.Header.Get("apns-push-type")
	m.lastPriority = r.Header.Get("apns-priority")
	m.lastCollapseID = r.Header.Get("apns-collapse-id")
	m.lastBody = append([]byte(nil), body...)
	status := m.nextStatus
	reason := m.nextReason
	timestamp := m.nextTimestamp
	m.nextStatus = 0
	m.nextReason = ""
	m.nextTimestamp = 0
	m.mu.Unlock()

	if status == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}
	// APNs error envelope: { "reason": "...", "timestamp": <ms> }.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if reason != "" {
		_, _ = w.Write(fmtAPNsError(reason, timestamp))
	}
}

// fmtAPNsError formats an APNs error response body. Keep it inline to
// avoid a dependency on encoding/json — the body shape is fixed.
func fmtAPNsError(reason string, timestampMillis int64) []byte {
	if timestampMillis == 0 {
		return []byte(`{"reason":"` + reason + `"}`)
	}
	return []byte(`{"reason":"` + reason + `","timestamp":` + itoa64(timestampMillis) + `}`)
}

// itoa64 is a strconv-free int64-to-decimal converter.
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
