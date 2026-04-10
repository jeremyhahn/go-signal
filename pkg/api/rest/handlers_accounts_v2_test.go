package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// handleChangeNumber
// --------------------------------------------------------------------------

func TestHandleChangeNumber_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{
		"number": "+15559999999",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {},
		"devicePniPqLastResortPrekeys": {},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp AccountIdentityResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if resp.UUID != testAccountUUID {
		t.Errorf("expected UUID %q, got %q", testAccountUUID, resp.UUID)
	}
	if resp.Number != "+15559999999" {
		t.Errorf("expected number +15559999999, got %q", resp.Number)
	}
	if resp.PNI == "" {
		t.Error("expected non-empty PNI")
	}

	// Verify the number was actually changed in the store.
	acct, err := s.accounts.Get(context.Background(), testAccountUUID)
	if err != nil {
		t.Fatalf("failed to get account: %v", err)
	}
	if acct.Number != "+15559999999" {
		t.Errorf("expected stored number +15559999999, got %q", acct.Number)
	}
}

func TestHandleChangeNumber_SameNumber(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{
		"number": "` + testAccountNumber + `",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {},
		"devicePniPqLastResortPrekeys": {},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleChangeNumber_EmptyNumber(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{
		"number": "",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {},
		"devicePniPqLastResortPrekeys": {},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleChangeNumber_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleChangeNumber_InvalidPniIdentityKey(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{
		"number": "+15559999999",
		"pniIdentityKey": "not-valid-base64!!!",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {},
		"devicePniPqLastResortPrekeys": {},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleChangeNumber_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	body := `{"number": "+15559999999"}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleChangeNumber_WithPniRegistrationIds(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{
		"number": "+15559999999",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {},
		"devicePniPqLastResortPrekeys": {},
		"pniRegistrationIds": {"1": 54321}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp AccountIdentityResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if resp.Number != "+15559999999" {
		t.Errorf("expected number +15559999999, got %q", resp.Number)
	}
}

func TestHandleChangeNumber_StorageCapable(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{
		"number": "+15559999999",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {},
		"devicePniPqLastResortPrekeys": {},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp AccountIdentityResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// The test account has storage capability set to true.
	if !resp.StorageCapable {
		t.Error("expected storageCapable to be true")
	}
}
