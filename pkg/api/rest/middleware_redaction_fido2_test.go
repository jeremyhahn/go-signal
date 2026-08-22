//go:build fido2

package rest

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// newFIDO2LoggingHarness registers the REAL FIDO2 route table behind the REAL
// loggingMiddleware and captures what the middleware writes.
//
// The point of going through RegisterFIDO2Routes rather than hand-written
// paths is that credentialPathPrefixes is a list of string literals: it can
// silently stop matching if a route is renamed. Driving the registered mux and
// requiring a non-404 proves the prefix and the route still describe the same
// endpoint.
func newFIDO2LoggingHarness(t *testing.T) (http.Handler, *bytes.Buffer) {
	t.Helper()

	s, _ := newTestServerWithAccount(t)
	mgr, _ := newTestFIDO2Manager(&mockFIDO2WebAuthnProvider{})

	mux := http.NewServeMux()
	s.routes(mux)
	RegisterFIDO2Routes(s, mux, mgr, testFIDO2Config())

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	return jsonMiddleware(loggingMiddleware(logger, mux)), &buf
}

// TestFIDO2Routes_DoNotLogCeremonyID is the fido2-tagged half of the #40
// regression: a registration ceremony id, taken from a live session, must not
// survive into the access log on any route that carries it in the path.
func TestFIDO2Routes_DoNotLogCeremonyID(t *testing.T) {
	handler, logged := newFIDO2LoggingHarness(t)

	// Begin a real registration so the id below is a live ceremony handle and
	// not a string that happens to look like one.
	beginRR := httptest.NewRecorder()
	handler.ServeHTTP(beginRR, httptest.NewRequest(
		http.MethodPost, "/v1/fido2/session", strings.NewReader(`{"username":"alice"}`)))
	require.Equal(t, http.StatusOK, beginRR.Code)

	var begin FIDO2BeginResponse
	require.NoError(t, json.Unmarshal(beginRR.Body.Bytes(), &begin))
	sessionID := begin.Session.SessionID
	require.NotEmpty(t, sessionID)

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		{"get session", http.MethodGet, "/v1/fido2/session/" + sessionID},
		{"complete registration", http.MethodPost, "/v1/fido2/session/" + sessionID + "/complete"},
		{"complete enrollment", http.MethodPost, "/v1/fido2/enroll/" + sessionID + "/complete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logged.Reset()

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.target, nil))

			// 404 here means the mux did not match, so a passing redaction
			// assertion would prove nothing about the real endpoint.
			require.NotEqual(t, http.StatusNotFound, rr.Code,
				"%s %s is no longer a registered route — update credentialPathPrefixes with it",
				tc.method, tc.target)

			out := logged.String()
			if strings.Contains(out, sessionID) {
				t.Errorf("the ceremony id reached the log:\n%s", out)
			}
			if !strings.Contains(out, redactedSegment) {
				t.Errorf("the request was not logged, or the route is unidentifiable:\n%s", out)
			}
		})
	}
}

// The credential id is a public handle the server hands out in
// allowCredentials, and it is what an operator correlates a key by. Redacting
// it would cost debuggability and buy nothing.
func TestFIDO2Routes_KeepCredentialID(t *testing.T) {
	handler, logged := newFIDO2LoggingHarness(t)

	const credID = "cred-visible-in-logs"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/v1/fido2/credentials/"+credID, nil))
	require.NotEqual(t, http.StatusNotFound, rr.Code)

	if !strings.Contains(logged.String(), credID) {
		t.Errorf("the credential id was redacted; it is not a credential:\n%s", logged.String())
	}
}
