package rest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// DeleteAccount, ChangeNumber, LinkDevice and SetRegistrationLock audit DENIED, FAILURE and SUCCESS; these tests cover the nil-safe helpers.

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
