package rest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testUsernameHash returns a deterministic 32-byte hash from the given seed
// string, satisfying the usernameHashLength validation.
func testUsernameHash(seed string) []byte {
	h := sha256.Sum256([]byte(seed))
	return h[:]
}

// --------------------------------------------------------------------------
// handleReserveUsernameHash
// --------------------------------------------------------------------------

func TestHandleReserveUsernameHash_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	hashB64 := base64.StdEncoding.EncodeToString(testUsernameHash("username-hash-data"))
	body := `{"usernameHashes":["` + hashB64 + `"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp UsernameHashReserveResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.UsernameHash == "" {
		t.Error("expected non-empty usernameHash")
	}
}

func TestHandleReserveUsernameHash_EmptyHashes(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"usernameHashes":[]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleReserveUsernameHash_InvalidBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"usernameHashes":["!!!not-base64!!!"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleReserveUsernameHash_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleReserveUsernameHash_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleConfirmUsernameHash
// --------------------------------------------------------------------------

func TestHandleConfirmUsernameHash_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Reserve first.
	hashB64 := base64.StdEncoding.EncodeToString(testUsernameHash("confirm-hash-data"))
	reserveBody := `{"usernameHashes":["` + hashB64 + `"]}`
	reserveReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(reserveBody))
	reserveReq.SetBasicAuth(testAccountUUID, testAuthToken)
	reserveRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(reserveRR, reserveReq)

	if reserveRR.Code != http.StatusOK {
		t.Fatalf("reserve failed: %d: %s", reserveRR.Code, reserveRR.Body.String())
	}

	// Confirm.
	token := "reservation-token-" + testAccountUUID
	confirmBody := `{"usernameHash":"` + hashB64 + `","reservationToken":"` + token + `"}`
	confirmReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader(confirmBody))
	confirmReq.SetBasicAuth(testAccountUUID, testAuthToken)
	confirmRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(confirmRR, confirmReq)

	if confirmRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", confirmRR.Code, confirmRR.Body.String())
	}
}

func TestHandleConfirmUsernameHash_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleConfirmUsernameHash_InvalidBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"usernameHash":"!!!","reservationToken":"tok"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleConfirmUsernameHash_EmptyToken(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	hashB64 := base64.StdEncoding.EncodeToString([]byte("hash"))
	body := `{"usernameHash":"` + hashB64 + `","reservationToken":""}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleConfirmUsernameHash_InvalidToken(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	hashB64 := base64.StdEncoding.EncodeToString([]byte("hash"))
	body := `{"usernameHash":"` + hashB64 + `","reservationToken":"wrong-token"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rr.Code)
	}
}

func TestHandleConfirmUsernameHash_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleDeleteUsernameHash
// --------------------------------------------------------------------------

func TestHandleDeleteUsernameHash_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Reserve and confirm first.
	hashB64 := base64.StdEncoding.EncodeToString(testUsernameHash("delete-hash"))
	reserveBody := `{"usernameHashes":["` + hashB64 + `"]}`
	reserveReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(reserveBody))
	reserveReq.SetBasicAuth(testAccountUUID, testAuthToken)
	reserveRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(reserveRR, reserveReq)

	token := "reservation-token-" + testAccountUUID
	confirmBody := `{"usernameHash":"` + hashB64 + `","reservationToken":"` + token + `"}`
	confirmReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader(confirmBody))
	confirmReq.SetBasicAuth(testAccountUUID, testAuthToken)
	confirmRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(confirmRR, confirmReq)

	// Delete.
	delReq := httptest.NewRequest(http.MethodDelete, "/v1/accounts/username_hash", nil)
	delReq.SetBasicAuth(testAccountUUID, testAuthToken)
	delRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(delRR, delReq)

	if delRR.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", delRR.Code, delRR.Body.String())
	}
}

func TestHandleDeleteUsernameHash_NotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/username_hash", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleDeleteUsernameHash_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/username_hash", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleLookupUsernameHash
// --------------------------------------------------------------------------

func TestHandleLookupUsernameHash_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Reserve and confirm.
	hashBytes := testUsernameHash("lookup-hash-data")
	hashB64 := base64.StdEncoding.EncodeToString(hashBytes)
	reserveBody := `{"usernameHashes":["` + hashB64 + `"]}`
	reserveReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(reserveBody))
	reserveReq.SetBasicAuth(testAccountUUID, testAuthToken)
	reserveRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(reserveRR, reserveReq)

	token := "reservation-token-" + testAccountUUID
	confirmBody := `{"usernameHash":"` + hashB64 + `","reservationToken":"` + token + `"}`
	confirmReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader(confirmBody))
	confirmReq.SetBasicAuth(testAccountUUID, testAuthToken)
	confirmRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(confirmRR, confirmReq)

	// Lookup uses URL encoding for the path.
	hashURLB64 := base64.URLEncoding.EncodeToString(hashBytes)
	lookupReq := httptest.NewRequest(http.MethodGet, "/v1/accounts/username_hash/"+hashURLB64, nil)
	lookupRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(lookupRR, lookupReq)

	if lookupRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", lookupRR.Code, lookupRR.Body.String())
	}

	var resp UsernameHashLookupResponse
	if err := json.Unmarshal(lookupRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.UUID != testAccountUUID {
		t.Errorf("expected UUID %s, got %s", testAccountUUID, resp.UUID)
	}
}

func TestHandleLookupUsernameHash_NotFound(t *testing.T) {
	s := newTestServer(t)

	hashURLB64 := base64.URLEncoding.EncodeToString([]byte("nonexistent"))
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/username_hash/"+hashURLB64, nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleLookupUsernameHash_InvalidBase64(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/username_hash/!!!not-url-safe-base64", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleLookupUsernameHash_AcceptsAuthenticatedRequests(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	hashURLB64 := base64.URLEncoding.EncodeToString([]byte("some-hash"))
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/username_hash/"+hashURLB64, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Authenticated requests are accepted — returns 404 since hash doesn't exist.
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for authenticated request with non-existent hash, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleSetUsernameLink
// --------------------------------------------------------------------------

func TestHandleSetUsernameLink_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	encValB64 := base64.StdEncoding.EncodeToString([]byte("encrypted-username"))
	body := `{"usernameLinkEncryptedValue":"` + encValB64 + `"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp UsernameLinkSetResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.UsernameLinkHandle == "" {
		t.Error("expected non-empty handle")
	}
}

func TestHandleSetUsernameLink_EmptyValue(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"usernameLinkEncryptedValue":""}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSetUsernameLink_InvalidBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"usernameLinkEncryptedValue":"!!!not-base64!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSetUsernameLink_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSetUsernameLink_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleDeleteUsernameLink
// --------------------------------------------------------------------------

func TestHandleDeleteUsernameLink_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Set link first.
	encValB64 := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	setBody := `{"usernameLinkEncryptedValue":"` + encValB64 + `"}`
	setReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader(setBody))
	setReq.SetBasicAuth(testAccountUUID, testAuthToken)
	setRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(setRR, setReq)

	// Delete.
	delReq := httptest.NewRequest(http.MethodDelete, "/v1/accounts/username_link", nil)
	delReq.SetBasicAuth(testAccountUUID, testAuthToken)
	delRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(delRR, delReq)

	if delRR.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", delRR.Code, delRR.Body.String())
	}
}

func TestHandleDeleteUsernameLink_NotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/username_link", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleDeleteUsernameLink_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/username_link", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleLookupUsernameLink
// --------------------------------------------------------------------------

func TestHandleLookupUsernameLink_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Set link first.
	encValB64 := base64.StdEncoding.EncodeToString([]byte("encrypted-data"))
	setBody := `{"usernameLinkEncryptedValue":"` + encValB64 + `"}`
	setReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader(setBody))
	setReq.SetBasicAuth(testAccountUUID, testAuthToken)
	setRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(setRR, setReq)

	var setResp UsernameLinkSetResponse
	if err := json.Unmarshal(setRR.Body.Bytes(), &setResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Lookup.
	lookupReq := httptest.NewRequest(http.MethodGet, "/v1/accounts/username_link/"+setResp.UsernameLinkHandle, nil)
	lookupRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(lookupRR, lookupReq)

	if lookupRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", lookupRR.Code, lookupRR.Body.String())
	}

	var resp UsernameLinkLookupResponse
	if err := json.Unmarshal(lookupRR.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.UsernameLinkEncryptedValue == "" {
		t.Error("expected non-empty encrypted value")
	}
}

func TestHandleLookupUsernameLink_NotFound(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/username_link/nonexistent-handle", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleLookupUsernameLink_AcceptsAuthenticatedRequests(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/username_link/some-handle", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Authenticated requests are accepted — returns 404 since handle doesn't exist.
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for authenticated request with non-existent handle, got %d", rr.Code)
	}
}
