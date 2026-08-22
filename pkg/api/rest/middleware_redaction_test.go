package rest

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// runThroughLoggingMiddleware drives the REAL loggingMiddleware and returns
// everything it wrote. Testing redactPathSegments alone would not prove the
// middleware calls it — the defect was precisely that the middleware redacted
// the query string and logged the path verbatim.
func runThroughLoggingMiddleware(t *testing.T, target string) string {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	h := loggingMiddleware(logger, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, target, nil))
	return buf.String()
}

// TestLoggingMiddleware_DoesNotLogVerificationSessionID is the regression test
// for #40.
//
// A verification session id is what POST /v1/registration accepts as proof of
// verification, so an access log containing it hands account takeover to
// anyone who can read logs — an operator, a log shipper, a backup, a support
// bundle.
func TestLoggingMiddleware_DoesNotLogVerificationSessionID(t *testing.T) {
	const sessionID = "e81a353c-356d-404d-b60c-b1040ea70f7b"

	for _, target := range []string{
		"/v1/verification/session/" + sessionID,
		"/v1/verification/session/" + sessionID + "/code",
	} {
		t.Run(target, func(t *testing.T) {
			out := runThroughLoggingMiddleware(t, target)

			if strings.Contains(out, sessionID) {
				t.Errorf("the session id reached the log — it is a registration credential:\n%s", out)
			}
			// The route must still be identifiable, or the log is useless.
			if !strings.Contains(out, "/v1/verification/session/"+redactedSegment) {
				t.Errorf("the route is no longer identifiable in the log:\n%s", out)
			}
		})
	}
}

func TestLoggingMiddleware_DoesNotLogUsernameLinkHandle(t *testing.T) {
	const handle = "b6f4e1a0-1111-2222-3333-444455556666"

	out := runThroughLoggingMiddleware(t, "/v1/accounts/username_link/"+handle)

	if strings.Contains(out, handle) {
		t.Errorf("the username-link handle reached the log:\n%s", out)
	}
}

// A FIDO2 ceremony id is the handle that completes a WebAuthn registration or
// enrollment, so it belongs to the same class as a verification session id.
// The routes only exist under the fido2 build tag; the policy does not, and
// this test holds it that way. middleware_redaction_fido2_test.go proves the
// prefixes still match the routes that are actually registered.
func TestLoggingMiddleware_DoesNotLogFIDO2CeremonyID(t *testing.T) {
	const ceremonyID = "9f2a7c41-5555-6666-7777-888899990000"

	for _, target := range []string{
		"/v1/fido2/session/" + ceremonyID,
		"/v1/fido2/session/" + ceremonyID + "/complete",
		"/v1/fido2/enroll/" + ceremonyID + "/complete",
	} {
		t.Run(target, func(t *testing.T) {
			out := runThroughLoggingMiddleware(t, target)

			if strings.Contains(out, ceremonyID) {
				t.Errorf("the ceremony id reached the log — it completes an authenticator binding:\n%s", out)
			}
			if !strings.Contains(out, redactedSegment) {
				t.Errorf("the route is no longer identifiable in the log:\n%s", out)
			}
		})
	}
}

// Redaction must not swallow the parts of the path an operator needs. Account
// identifiers stay: they are the primary correlation key and are not bearer
// credentials. So do FIDO2 credential ids — the server publishes those itself
// in allowCredentials.
func TestLoggingMiddleware_KeepsNonCredentialPaths(t *testing.T) {
	const acct = "11111111-2222-3333-4444-555555555555"

	for _, target := range []string{
		"/v1/profile/" + acct,
		"/v2/keys/" + acct + "/1",
		"/v1/fido2/credentials/cred-1",
		"/v1/keepalive",
	} {
		t.Run(target, func(t *testing.T) {
			out := runThroughLoggingMiddleware(t, target)
			if !strings.Contains(out, target) {
				t.Errorf("path %q was altered in the log; only credential segments should be:\n%s",
					target, out)
			}
		})
	}
}

// The query redaction that already existed must survive alongside the new
// path redaction, including on a credential-bearing path.
func TestLoggingMiddleware_RedactsBothPathAndQuery(t *testing.T) {
	const sessionID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	out := runThroughLoggingMiddleware(t,
		"/v1/verification/session/"+sessionID+"/code?login=alice&password=hunter2")

	if strings.Contains(out, sessionID) {
		t.Errorf("session id leaked:\n%s", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Errorf("password leaked:\n%s", out)
	}
}

// A collection endpoint carries no credential and must be left alone.
func TestRedactPathSegments_CollectionEndpointUnchanged(t *testing.T) {
	const p = "/v1/verification/session/"
	if got := redactPathSegments(p); got != p {
		t.Errorf("redactPathSegments(%q) = %q, want it unchanged", p, got)
	}
}
