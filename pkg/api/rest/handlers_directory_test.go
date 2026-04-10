package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleGetDirectoryAuth_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/directory/auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetDirectoryAuth_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/directory/auth", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleDirectoryLookup
// --------------------------------------------------------------------------

func TestHandleDirectoryLookup_RegisteredNumber(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"numbers":["+15551234567"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Contacts []struct {
			E164 string `json:"e164"`
			UUID string `json:"uuid"`
		} `json:"contacts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Contacts) != 1 {
		t.Fatalf("expected 1 contact, got %d", len(resp.Contacts))
	}
	if resp.Contacts[0].E164 != "+15551234567" {
		t.Errorf("expected E164 +15551234567, got %q", resp.Contacts[0].E164)
	}
	if resp.Contacts[0].UUID != testAccountUUID {
		t.Errorf("expected UUID %s, got %q", testAccountUUID, resp.Contacts[0].UUID)
	}
}

func TestHandleDirectoryLookup_UnknownNumber(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"numbers":["+15559999999"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Contacts []json.RawMessage `json:"contacts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Contacts) != 0 {
		t.Errorf("expected 0 contacts for unknown number, got %d", len(resp.Contacts))
	}
}

func TestHandleDirectoryLookup_AcceptsUnauthenticated(t *testing.T) {
	s := newTestServer(t)

	// Directory lookup uses its own service credentials, not account auth.
	// Unauthenticated requests are accepted (rate limited by IP).
	body := `{"numbers":["+15559999999"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleDirectoryLookup_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader("not json"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleDirectoryLookup_EmptyNumbers(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"numbers":[]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Contacts []json.RawMessage `json:"contacts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Contacts) != 0 {
		t.Errorf("expected 0 contacts for empty numbers, got %d", len(resp.Contacts))
	}
}

func TestHandleDirectoryLookup_MixedKnownAndUnknown(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"numbers":["+15551234567","+15559999999"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Contacts []struct {
			E164 string `json:"e164"`
			UUID string `json:"uuid"`
		} `json:"contacts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Contacts) != 1 {
		t.Fatalf("expected 1 contact (only registered), got %d", len(resp.Contacts))
	}
	if resp.Contacts[0].E164 != "+15551234567" {
		t.Errorf("expected registered number, got %q", resp.Contacts[0].E164)
	}
}
