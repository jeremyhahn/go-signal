//go:build integration

// Package mocks provides reusable fake servers for the upstream
// services Phase 3 ships against: Twilio Verify (SMS verification),
// APNs (Apple Push), and FCM (Firebase Cloud Messaging). Each mock is
// a thin httptest.Server that replays just enough of the real protocol
// for go-signal's clients to exercise their full code path.
//
// Mocks are intentionally permissive: they accept any auth credential
// shape (no SigV4 / JWT validation) so tests can wire the providers
// against arbitrary placeholder keys. The goal is to assert the
// CLIENT-side behavior (headers, request bodies, status mapping), not
// to certify the upstream services' own correctness.
package mocks

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// TwilioMock is a fake Twilio Verify REST API. It accepts
//
//	POST /Services/{sid}/Verifications      → "Send code"
//	POST /Services/{sid}/VerificationCheck  → "Submit code"
//
// and records the last (To, Channel, Code) tuple each test can assert.
type TwilioMock struct {
	Server *httptest.Server

	mu       sync.Mutex
	lastTo   string
	lastChan string
	lastCode string
	// approvedCodes is the set of (To,Code) pairs the next
	// VerificationCheck call will treat as "approved". Pre-populate via
	// Approve(); empty means "always pending".
	approvedCodes map[string]struct{}
	// nextStatus overrides the HTTP status for the next /Verifications
	// call — used by tests that exercise error paths. Zero defaults to
	// 201 Created.
	nextStatus int
	// nextBody overrides the response body for the next /Verifications
	// call. Empty defaults to the success envelope.
	nextBody string
}

// NewTwilioMock returns a started mock server. The caller must Close
// when done (or rely on t.Cleanup).
func NewTwilioMock() *TwilioMock {
	m := &TwilioMock{approvedCodes: make(map[string]struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.serve)
	m.Server = httptest.NewServer(mux)
	return m
}

// Close shuts the underlying httptest.Server down.
func (m *TwilioMock) Close() { m.Server.Close() }

// URL returns the mock's base URL — pass it as twilio.Config.BaseURL.
func (m *TwilioMock) URL() string { return m.Server.URL }

// Approve marks (to, code) as a valid pair so the next
// VerificationCheck call returns status="approved".
func (m *TwilioMock) Approve(to, code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.approvedCodes[to+"|"+code] = struct{}{}
}

// LastSend returns the most recent (To, Channel, Code) recorded by the
// mock. Code is the fake-generated code the mock issues — production
// Twilio Verify owns code generation, so we mint a deterministic one
// per Twilio "To" the first time SendCode runs.
func (m *TwilioMock) LastSend() (to, channel, code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastTo, m.lastChan, m.lastCode
}

// SetNextResponse forces the next /Verifications request to respond
// with status + body. Caller-supplied error fixtures use this to drive
// the negative path through the transport.
func (m *TwilioMock) SetNextResponse(status int, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextStatus = status
	m.nextBody = body
}

// serve dispatches to the matching Twilio endpoint. We use suffix-match
// on the URL path rather than the trie ServeMux would build because
// real Twilio embeds the service SID in the path — we don't care
// which SID the client used.
func (m *TwilioMock) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/Verifications"):
		m.handleSend(w, r)
	case strings.HasSuffix(r.URL.Path, "/VerificationCheck"):
		m.handleCheck(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (m *TwilioMock) handleSend(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	values := parseForm(string(body))

	m.mu.Lock()
	to := values["To"]
	channel := values["Channel"]
	// Deterministic per-(To) code so tests can submit it back without a
	// round-trip through the mock body. "123456" is the literal
	// FixedCode the verification.Manager uses in test mode; the symmetry
	// is intentional.
	code := "123456"
	m.lastTo = to
	m.lastChan = channel
	m.lastCode = code
	status := m.nextStatus
	body2 := m.nextBody
	m.nextStatus = 0
	m.nextBody = ""
	m.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body2))
		return
	}
	resp, _ := json.Marshal(map[string]string{"sid": "VEtest", "status": "pending"})
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(resp)
}

func (m *TwilioMock) handleCheck(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	values := parseForm(string(body))
	to := values["To"]
	code := values["Code"]

	m.mu.Lock()
	_, approved := m.approvedCodes[to+"|"+code]
	m.mu.Unlock()

	status := "pending"
	if approved {
		status = "approved"
	}
	w.WriteHeader(http.StatusOK)
	resp, _ := json.Marshal(map[string]string{"sid": "VCtest", "status": status})
	_, _ = w.Write(resp)
}

// parseForm is a tiny urlencoded form decoder that handles the small
// set of fields Twilio Verify accepts (To, Channel, Code). Using the
// stdlib net/url would pull in extra error-handling code for no benefit
// since the mock controls the request shape end-to-end.
func parseForm(body string) map[string]string {
	out := make(map[string]string)
	for _, pair := range strings.Split(body, "&") {
		if pair == "" {
			continue
		}
		eq := strings.Index(pair, "=")
		if eq < 0 {
			continue
		}
		key := pair[:eq]
		val := pair[eq+1:]
		out[key] = urlDecode(val)
	}
	return out
}

// urlDecode handles only the percent-encoding cases Twilio's form
// submissions produce: '+' for space, '%XX' for byte escapes. Anything
// malformed is returned verbatim — the mock never sees pathological
// input from the in-process client.
func urlDecode(s string) string {
	if !strings.ContainsAny(s, "+%") {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '+':
			sb.WriteByte(' ')
		case s[i] == '%' && i+2 < len(s):
			v, ok := hexPair(s[i+1], s[i+2])
			if !ok {
				sb.WriteByte(s[i])
				continue
			}
			sb.WriteByte(v)
			i += 2
		default:
			sb.WriteByte(s[i])
		}
	}
	return sb.String()
}

// hexPair turns two ASCII hex digits into the corresponding byte.
func hexPair(a, b byte) (byte, bool) {
	x, ok1 := hexNybble(a)
	y, ok2 := hexNybble(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return (x << 4) | y, true
}

func hexNybble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
