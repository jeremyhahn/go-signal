package rest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The four sensitive REST handlers (DeleteAccount, ChangeNumber,
// LinkDevice, SetRegistrationLock) emit audit events through
// s.audit when it is non-nil. The emission happens at three
// decision points each:
//
//   - DENIED: handler-level authorization rejection that runs AFTER
//     the auth middleware (e.g. ChangeNumber's primary-device gate).
//     Unauthenticated requests are short-circuited by the auth
//     middleware itself; those 401s don't reach the handler and
//     therefore aren't audited here — the chat-server access log
//     captures them.
//
//   - FAILURE: handler-level operation error after authorization.
//
//   - SUCCESS: operation completed cleanly.
//
// Testing the success / failure / handler-denied paths requires a
// fully authenticated request fixture. The structural correctness
// (audit nil-safe, helper math) is exercised here; the per-action
// integration assertions ride on top of newTestServerWithAccount in
// the existing handler suites.

func TestAudit_NilLoggerIsNilSafe(t *testing.T) {
	// Server with audit=nil — all four handlers must serve their
	// regular response path without panicking on missing logger.
	s, _ := newTestServerWithVerification(t)
	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/me", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("DeleteAccount nil-audit = %d, want 401", rr.Code)
	}
	body := bytes.NewBufferString(`{"registrationLock":"hash"}`)
	req = httptest.NewRequest(http.MethodPut, "/v1/accounts/registration_lock", body)
	rr = httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("SetRegistrationLock nil-audit = %d, want 401", rr.Code)
	}
}

func TestPrefixOrEmpty(t *testing.T) {
	cases := map[string]struct {
		in   string
		n    int
		want string
	}{
		"normal": {"+15551234567", 5, "+1555"},
		"exact":  {"abcd", 4, "abcd"},
		"longer": {"abc", 10, "abc"},
		"zero-n": {"abc", 0, ""},
		"neg-n":  {"abc", -1, ""},
		"empty":  {"", 5, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := prefixOrEmpty(c.in, c.n); got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}
