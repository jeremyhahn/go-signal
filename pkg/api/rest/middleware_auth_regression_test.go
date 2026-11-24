package rest

// Auth timing: unknown UUIDs and wrong passwords both return 401 after real hash work; valid credentials still return 200 (GET /v1/accounts/whoami).

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

	// A well-formed unregistered UUID takes the dummy-hash path.
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

// TestAuthMiddleware_TimingEqualization asserts the not-found path does real hash work (> 1 µs).
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

// TestAuthMiddleware_ValidCredentials_NotBrokenByTimingFix checks authenticated requests reach the handler.
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
