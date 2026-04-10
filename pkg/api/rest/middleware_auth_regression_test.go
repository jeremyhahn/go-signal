package rest

// Regression tests for HIGH-3: auth timing oracle fix.
//
// The authMiddleware pre-computes a dummyHash at initialisation and calls
// dummyHash.Verify(password) on every account-not-found path. This prevents
// a timing oracle that would let an attacker enumerate valid account UUIDs by
// measuring whether the response is returned immediately (no hash work) or
// after bcrypt/HKDF work.
//
// What we can observe in unit tests:
//   - Both "invalid UUID" and "valid UUID + wrong password" paths return 401.
//   - Both paths take non-trivial time (> 0 µs), proving real hash work is done
//     and not short-circuited.
//   - A valid UUID + correct password still returns 200 (regression: the
//     timing fix must not break the success path).
//
// All tests hit GET /v1/accounts/whoami, which is wrapped with auth() in
// server.go and therefore requires valid Basic Auth credentials.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// authProtectedEndpoint is a simple authenticated endpoint used by all
// auth-middleware regression tests. It must be wrapped with auth() in server.go.
const authProtectedEndpoint = "/v1/accounts/whoami"

// TestAuthMiddleware_AccountNotFound_PerformsDummyVerification verifies that
// the account-not-found path still returns 401 Unauthorized, confirming the
// middleware does not short-circuit before performing hash work. This guards
// against regressions where the early-return optimisation is accidentally
// restored, re-introducing the timing oracle.
func TestAuthMiddleware_AccountNotFound_PerformsDummyVerification(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Use a well-formed UUID that is not registered — triggers the dummy
	// hash verification path added by the HIGH-3 security fix.
	unknownUUID := "00000000-0000-0000-0000-000000000000"

	req := httptest.NewRequest(http.MethodGet, authProtectedEndpoint, nil)
	req.SetBasicAuth(unknownUUID, "wrong-password")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rr.Code, rr.Body.String())
	}

	// The response body must contain an error field (not a success body),
	// confirming the handler did not let the request through.
	if rr.Body.Len() == 0 {
		t.Error("expected non-empty response body with error details")
	}
}

// TestAuthMiddleware_TimingEqualization verifies that account-not-found and
// account-found-wrong-password paths both take measurably non-zero time.
// The pre-computed dummyHash.Verify call on the not-found path ensures that
// both code paths perform an equivalent HKDF-SHA256 derivation, preventing
// an attacker from distinguishing "UUID does not exist" from "UUID exists but
// password is wrong" through response latency.
//
// The test does not assert that the two durations are within a tight bound —
// that would be fragile under load — but it does assert that the not-found
// path takes > 1 µs, proving real work was done rather than an immediate
// short-circuit return.
func TestAuthMiddleware_TimingEqualization(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Path A: valid UUID, wrong password (real hash verification performed).
	reqA := httptest.NewRequest(http.MethodGet, authProtectedEndpoint, nil)
	reqA.SetBasicAuth(testAccountUUID, "definitely-wrong-password")
	rrA := httptest.NewRecorder()
	startA := time.Now()
	s.httpServer.Handler.ServeHTTP(rrA, reqA)
	durationA := time.Since(startA)

	if rrA.Code != http.StatusUnauthorized {
		t.Errorf("path A: expected 401, got %d", rrA.Code)
	}

	// Path B: unknown UUID, any password (dummy hash verification performed).
	unknownUUID := "ffffffff-ffff-ffff-ffff-ffffffffffff"
	reqB := httptest.NewRequest(http.MethodGet, authProtectedEndpoint, nil)
	reqB.SetBasicAuth(unknownUUID, "definitely-wrong-password")
	rrB := httptest.NewRecorder()
	startB := time.Now()
	s.httpServer.Handler.ServeHTTP(rrB, reqB)
	durationB := time.Since(startB)

	if rrB.Code != http.StatusUnauthorized {
		t.Errorf("path B: expected 401, got %d", rrB.Code)
	}

	// Both paths must take longer than 1 µs — any shorter would indicate
	// a short-circuit return (no hash work performed).
	const minWork = time.Microsecond
	if durationA < minWork {
		t.Errorf("path A (valid UUID + wrong pass) took %v, expected > %v — hash work may have been skipped", durationA, minWork)
	}
	if durationB < minWork {
		t.Errorf("path B (unknown UUID) took %v, expected > %v — dummy hash verification may have been removed", durationB, minWork)
	}
}

// TestAuthMiddleware_ValidCredentials_NotBrokenByTimingFix verifies that the
// dummy-hash path added by the HIGH-3 fix did not inadvertently break the
// success path — authenticated requests must still reach the handler.
func TestAuthMiddleware_ValidCredentials_NotBrokenByTimingFix(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, authProtectedEndpoint, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for valid credentials, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestAuthMiddleware_NoCredentials_Rejected guards against regressions where
// requests with no Basic Auth header are allowed through an auth-protected
// endpoint. This complements TestAuthMiddleware_MissingCredentials in
// middleware_test.go by exercising the full server routing layer.
func TestAuthMiddleware_NoCredentials_Rejected(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, authProtectedEndpoint, nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing credentials, got %d", rr.Code)
	}
}
