package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// handleChangeNumber
// --------------------------------------------------------------------------

// changeNumberServer builds a test server with the standard account plus a
// verified verification session for newNumber. handleChangeNumber now requires
// proof of ownership of the target number, so the returned session ID must be
// placed in the request body's "sessionId" field.
func changeNumberServer(t *testing.T, newNumber string) (*Server, string) {
	t.Helper()
	s, transport := newTestServerWithVerification(t)
	if err := s.accounts.Create(context.Background(), testAccount()); err != nil {
		t.Fatalf("failed to create test account: %v", err)
	}
	sessionID := createVerifiedSession(t, s, transport, newNumber)
	return s, sessionID
}

func TestHandleChangeNumber_Success(t *testing.T) {
	s, sessionID := changeNumberServer(t, "+15559999999")

	body := `{
		"number": "+15559999999",
		"sessionId": "` + sessionID + `",
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
	s, sessionID := changeNumberServer(t, testAccountNumber)

	body := `{
		"number": "` + testAccountNumber + `",
		"sessionId": "` + sessionID + `",
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
	s, sessionID := changeNumberServer(t, "+15559999999")

	body := `{
		"number": "+15559999999",
		"sessionId": "` + sessionID + `",
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
	s, sessionID := changeNumberServer(t, "+15559999999")

	body := `{
		"number": "+15559999999",
		"sessionId": "` + sessionID + `",
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
	s, sessionID := changeNumberServer(t, "+15559999999")

	body := `{
		"number": "+15559999999",
		"sessionId": "` + sessionID + `",
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

// --------------------------------------------------------------------------
// validateChangeNumberPniKeys (exercised via handleChangeNumber)
// --------------------------------------------------------------------------

// TestHandleChangeNumber_InvalidPniSignedPrekeyBase64 verifies that a
// devicePniSignedPrekeys entry with an invalid base64 public key causes 400.
func TestHandleChangeNumber_InvalidPniSignedPrekeyBase64(t *testing.T) {
	s, sessionID := changeNumberServer(t, "+15559998888")

	body := `{
		"number": "+15559998888",
		"sessionId": "` + sessionID + `",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {
			"1": {"keyId": 1, "publicKey": "!!!bad-base64!!!", "signature": "` + testSignedPreKeySigB64 + `"}
		},
		"devicePniPqLastResortPrekeys": {},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid signed prekey pubkey base64, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleChangeNumber_InvalidPniSignedPrekeySignatureBase64 verifies that a
// devicePniSignedPrekeys entry with an invalid base64 signature causes 400.
func TestHandleChangeNumber_InvalidPniSignedPrekeySignatureBase64(t *testing.T) {
	s, sessionID := changeNumberServer(t, "+15559997777")

	body := `{
		"number": "+15559997777",
		"sessionId": "` + sessionID + `",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {
			"1": {"keyId": 1, "publicKey": "` + testSignedPreKeyPubB64 + `", "signature": "!!!bad-base64!!!"}
		},
		"devicePniPqLastResortPrekeys": {},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid signed prekey sig base64, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleChangeNumber_InvalidPniSignedPrekeySignature verifies that a
// devicePniSignedPrekeys entry whose signature is invalid (bad signature over
// the key) causes 422. The key is valid base64 but the ECDSA check fails.
func TestHandleChangeNumber_InvalidPniSignedPrekeySignature(t *testing.T) {
	s, sessionID := changeNumberServer(t, "+15559996666")

	// testSignedPreKeyPub is not signed by testPniIdentityKey, so the signature
	// validation will reject it with 422.
	body := `{
		"number": "+15559996666",
		"sessionId": "` + sessionID + `",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {
			"1": {"keyId": 1, "publicKey": "` + testSignedPreKeyPubB64 + `", "signature": "` + testSignedPreKeySigB64 + `"}
		},
		"devicePniPqLastResortPrekeys": {},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for invalid signed prekey signature, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleChangeNumber_InvalidPniPqLastResortPrekeyBase64 verifies that a
// devicePniPqLastResortPrekeys entry with invalid base64 public key causes 400.
func TestHandleChangeNumber_InvalidPniPqLastResortPrekeyBase64(t *testing.T) {
	km := getTestKeyMaterial(t)
	s, sessionID := changeNumberServer(t, "+15559995555")

	body := `{
		"number": "+15559995555",
		"sessionId": "` + sessionID + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {},
		"devicePniPqLastResortPrekeys": {
			"1": {"keyId": 1, "publicKey": "!!!bad-base64!!!", "signature": "` + km.PNIPqSigB64 + `"}
		},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid PQ prekey pubkey base64, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleChangeNumber_InvalidPniPqLastResortPrekeySignatureBase64 verifies
// that a devicePniPqLastResortPrekeys entry with invalid base64 signature causes 400.
func TestHandleChangeNumber_InvalidPniPqLastResortPrekeySignatureBase64(t *testing.T) {
	km := getTestKeyMaterial(t)
	s, sessionID := changeNumberServer(t, "+15559994444")

	body := `{
		"number": "+15559994444",
		"sessionId": "` + sessionID + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {},
		"devicePniPqLastResortPrekeys": {
			"1": {"keyId": 1, "publicKey": "` + km.PNIPqPubB64 + `", "signature": "!!!bad-sig!!!"}
		},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid PQ prekey sig base64, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleChangeNumber_InvalidPniPqLastResortPrekeySignature verifies that a
// devicePniPqLastResortPrekeys entry whose signature is invalid causes 422.
func TestHandleChangeNumber_InvalidPniPqLastResortPrekeySignature(t *testing.T) {
	km := getTestKeyMaterial(t)
	s, sessionID := changeNumberServer(t, "+15559993333")

	// testPniIdentityKey does not correspond to km.PNIKeyPair, so the
	// PQ key signed with km.PNIKeyPair will fail validation against testPniIdentityKey.
	badPub := base64.StdEncoding.EncodeToString([]byte("pq-pub-32bytes-xxxxxxxxxxxxxxxx"))
	body := `{
		"number": "+15559993333",
		"sessionId": "` + sessionID + `",
		"pniIdentityKey": "` + testPniIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {},
		"devicePniPqLastResortPrekeys": {
			"1": {"keyId": 1, "publicKey": "` + badPub + `", "signature": "` + km.PNIPqSigB64 + `"}
		},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for invalid PQ prekey signature, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleChangeNumber_PniSignedPrekeyWithoutPniIdentityKey verifies that
// providing devicePniSignedPrekeys without a pniIdentityKey causes 400.
func TestHandleChangeNumber_PniSignedPrekeyWithoutPniIdentityKey(t *testing.T) {
	s, sessionID := changeNumberServer(t, "+15559992222")

	body := `{
		"number": "+15559992222",
		"sessionId": "` + sessionID + `",
		"pniIdentityKey": "",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {
			"1": {"keyId": 1, "publicKey": "` + testSignedPreKeyPubB64 + `", "signature": "` + testSignedPreKeySigB64 + `"}
		},
		"devicePniPqLastResortPrekeys": {},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when PNI prekeys provided without pniIdentityKey, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleChangeNumber_StorePniSignedPrekeys exercises storeChangeNumberPniKeys
// by providing a valid signed PNI prekey that passes validateChangeNumberPniKeys.
// Device ID "1" matches the primary device of the test account so the key is
// actually stored.
func TestHandleChangeNumber_StorePniSignedPrekeys(t *testing.T) {
	km := getTestKeyMaterial(t)
	s, transport := newTestServerWithVerification(t)
	if err := s.accounts.Create(context.Background(), testAccount()); err != nil {
		t.Fatalf("failed to create test account: %v", err)
	}
	const newNumber = "+15559991111"
	sessionID := createVerifiedSession(t, s, transport, newNumber)
	_ = transport

	body := `{
		"number": "` + newNumber + `",
		"sessionId": "` + sessionID + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {
			"1": {"keyId": 2, "publicKey": "` + km.PNISignedPreKeyPubB64 + `", "signature": "` + km.PNISignedPreKeySigB64 + `"}
		},
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
	if resp.Number != newNumber {
		t.Errorf("expected number %q, got %q", newNumber, resp.Number)
	}
}

// TestHandleChangeNumber_StorePniPqLastResortPrekeys exercises the PQ prekey
// storage branch inside storeChangeNumberPniKeys. Device "1" matches the primary
// device of the test account so the PQ last-resort key is actually persisted.
func TestHandleChangeNumber_StorePniPqLastResortPrekeys(t *testing.T) {
	km := getTestKeyMaterial(t)
	s, transport := newTestServerWithVerification(t)
	if err := s.accounts.Create(context.Background(), testAccount()); err != nil {
		t.Fatalf("failed to create test account: %v", err)
	}
	const newNumber = "+15559990000"
	sessionID := createVerifiedSession(t, s, transport, newNumber)
	_ = transport

	body := `{
		"number": "` + newNumber + `",
		"sessionId": "` + sessionID + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {},
		"devicePniPqLastResortPrekeys": {
			"1": {"keyId": 3, "publicKey": "` + km.PNIPqPubB64 + `", "signature": "` + km.PNIPqSigB64 + `"}
		},
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

// TestHandleChangeNumber_StoreSkipsInvalidDeviceID verifies that
// storeChangeNumberPniKeys skips entries whose device ID is invalid
// (non-numeric, zero, or not present on the account). The request must still
// return 200 because invalid entries are silently ignored.
func TestHandleChangeNumber_StoreSkipsInvalidDeviceID(t *testing.T) {
	km := getTestKeyMaterial(t)
	s, transport := newTestServerWithVerification(t)
	if err := s.accounts.Create(context.Background(), testAccount()); err != nil {
		t.Fatalf("failed to create test account: %v", err)
	}
	const newNumber = "+15559989999"
	sessionID := createVerifiedSession(t, s, transport, newNumber)
	_ = transport

	// Device "99" does not exist on the test account; it should be silently skipped.
	body := `{
		"number": "` + newNumber + `",
		"sessionId": "` + sessionID + `",
		"pniIdentityKey": "` + km.PNIIdentityKeyB64 + `",
		"deviceMessages": [],
		"devicePniSignedPrekeys": {
			"99": {"keyId": 5, "publicKey": "` + km.PNISignedPreKeyPubB64 + `", "signature": "` + km.PNISignedPreKeySigB64 + `"}
		},
		"devicePniPqLastResortPrekeys": {
			"abc": {"keyId": 6, "publicKey": "` + km.PNIPqPubB64 + `", "signature": "` + km.PNIPqSigB64 + `"}
		},
		"pniRegistrationIds": {}
	}`
	req := httptest.NewRequest(http.MethodPut, "/v2/accounts/number", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (invalid device IDs should be skipped), got %d: %s", rr.Code, rr.Body.String())
	}
}
