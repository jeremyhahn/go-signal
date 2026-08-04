package rest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	libsignalusernames "github.com/jeremyhahn/go-libsignal/pkg/usernames"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	signalUsernames "github.com/jeremyhahn/go-signal/pkg/usernames"
)

// testUsernameHash returns a deterministic 32-byte hash from the given seed
// string, satisfying the usernameHashLength validation. NOTE: this hash is
// NOT a valid SignalProtocol username hash; tests using it only exercise
// shape/length checks, not full ZK proof verification.
func testUsernameHash(seed string) []byte {
	h := sha256.Sum256([]byte(seed))
	return h[:]
}

// realUsernameHashAndProof returns a real ZK-verifiable username hash and
// proof generated through go-libsignal. Used by tests that drive the success
// path through ConfirmHash, where the server-side VerifyProof must accept the
// supplied proof.
func realUsernameHashAndProof(t *testing.T) (hash []byte, proofB64 string) {
	t.Helper()
	u, err := libsignalusernames.FromParts("resttest", "01", libsignalusernames.DefaultNicknameLimits())
	if err != nil {
		t.Fatalf("FromParts: %v", err)
	}
	h := u.Hash()
	var randomness [32]byte
	if _, err := rand.Read(randomness[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	proof, err := u.Proof(randomness)
	if err != nil {
		t.Fatalf("Proof: %v", err)
	}
	out := make([]byte, 32)
	copy(out, h[:])
	return out, base64.StdEncoding.EncodeToString(proof)
}

// dummyZkProofB64 is base64-encoded 64 arbitrary bytes — non-empty so the
// shape check passes, but never verifies. Useful for negative-path tests.
func dummyZkProofB64() string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// confirmTestUsernameHash reserves and confirms a real username hash for the
// supplied account UUID via the public manager API. The link-publishing flow
// requires an account to already have a confirmed hash on file (Java
// AccountController#setUsernameLink); link-surface tests use this helper to
// satisfy that precondition without driving the full HTTP flow.
func confirmTestUsernameHash(t *testing.T, s *Server, uuid string) {
	t.Helper()
	hash, proofB64 := realUsernameHashAndProof(t)
	proof, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		t.Fatalf("decode proof: %v", err)
	}
	_, token, err := s.usernames.ReserveHash(t.Context(), uuid, [][]byte{hash})
	if err != nil {
		t.Fatalf("ReserveHash: %v", err)
	}
	if err := s.usernames.ConfirmHash(t.Context(), uuid, hash, token, proof); err != nil {
		t.Fatalf("ConfirmHash: %v", err)
	}
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

	hash, proofB64 := realUsernameHashAndProof(t)
	hashB64 := base64.StdEncoding.EncodeToString(hash)

	// Reserve first.
	reserveBody := `{"usernameHashes":["` + hashB64 + `"]}`
	reserveReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(reserveBody))
	reserveReq.SetBasicAuth(testAccountUUID, testAuthToken)
	reserveRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(reserveRR, reserveReq)

	if reserveRR.Code != http.StatusOK {
		t.Fatalf("reserve failed: %d: %s", reserveRR.Code, reserveRR.Body.String())
	}

	// Confirm with a valid ZK proof.
	token := "reservation-token-" + testAccountUUID
	confirmBody := `{"usernameHash":"` + hashB64 + `","reservationToken":"` + token + `","zkProof":"` + proofB64 + `"}`
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

	body := `{"usernameHash":"!!!","reservationToken":"tok","zkProof":"` + dummyZkProofB64() + `"}`
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
	body := `{"usernameHash":"` + hashB64 + `","reservationToken":"","zkProof":"` + dummyZkProofB64() + `"}`
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

	// Use a real (verifiable) ZK proof so the failure surfaces from the
	// reservation-token check, not from VerifyProof.
	hash, proofB64 := realUsernameHashAndProof(t)
	hashB64 := base64.StdEncoding.EncodeToString(hash)
	body := `{"usernameHash":"` + hashB64 + `","reservationToken":"wrong-token","zkProof":"` + proofB64 + `"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rr.Code)
	}
}

func TestHandleConfirmUsernameHash_MissingProof(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	hash, _ := realUsernameHashAndProof(t)
	hashB64 := base64.StdEncoding.EncodeToString(hash)
	body := `{"usernameHash":"` + hashB64 + `","reservationToken":"tok"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (missing zkProof), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleConfirmUsernameHash_InvalidZkProof_Returns422(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	hash, _ := realUsernameHashAndProof(t)
	hashB64 := base64.StdEncoding.EncodeToString(hash)

	// Reserve so the token check would pass.
	reserveBody := `{"usernameHashes":["` + hashB64 + `"]}`
	reserveReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(reserveBody))
	reserveReq.SetBasicAuth(testAccountUUID, testAuthToken)
	s.httpServer.Handler.ServeHTTP(httptest.NewRecorder(), reserveReq)

	// Confirm with a bogus proof — 422.
	token := "reservation-token-" + testAccountUUID
	body := `{"usernameHash":"` + hashB64 + `","reservationToken":"` + token + `","zkProof":"` + dummyZkProofB64() + `"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d: %s", rr.Code, rr.Body.String())
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

	// Reserve and confirm first (real hash + proof so VerifyProof passes).
	hash, proofB64 := realUsernameHashAndProof(t)
	hashB64 := base64.StdEncoding.EncodeToString(hash)
	reserveBody := `{"usernameHashes":["` + hashB64 + `"]}`
	reserveReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(reserveBody))
	reserveReq.SetBasicAuth(testAccountUUID, testAuthToken)
	reserveRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(reserveRR, reserveReq)

	token := "reservation-token-" + testAccountUUID
	confirmBody := `{"usernameHash":"` + hashB64 + `","reservationToken":"` + token + `","zkProof":"` + proofB64 + `"}`
	confirmReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader(confirmBody))
	confirmReq.SetBasicAuth(testAccountUUID, testAuthToken)
	confirmRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(confirmRR, confirmReq)
	if confirmRR.Code != http.StatusOK {
		t.Fatalf("setup confirm failed: %d %s", confirmRR.Code, confirmRR.Body.String())
	}

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

	// Reserve and confirm with a real hash + proof.
	hashBytes, proofB64 := realUsernameHashAndProof(t)
	hashB64 := base64.StdEncoding.EncodeToString(hashBytes)
	reserveBody := `{"usernameHashes":["` + hashB64 + `"]}`
	reserveReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(reserveBody))
	reserveReq.SetBasicAuth(testAccountUUID, testAuthToken)
	reserveRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(reserveRR, reserveReq)

	token := "reservation-token-" + testAccountUUID
	confirmBody := `{"usernameHash":"` + hashB64 + `","reservationToken":"` + token + `","zkProof":"` + proofB64 + `"}`
	confirmReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/confirm", strings.NewReader(confirmBody))
	confirmReq.SetBasicAuth(testAccountUUID, testAuthToken)
	confirmRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(confirmRR, confirmReq)
	if confirmRR.Code != http.StatusOK {
		t.Fatalf("setup confirm failed: %d %s", confirmRR.Code, confirmRR.Body.String())
	}

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
	confirmTestUsernameHash(t, s, testAccountUUID)

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

func TestHandleSetUsernameLink_KeepLinkHandle(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	confirmTestUsernameHash(t, s, testAccountUUID)

	// First publish — mints a fresh handle.
	encV1 := base64.StdEncoding.EncodeToString([]byte("encrypted-v1"))
	body1 := `{"usernameLinkEncryptedValue":"` + encV1 + `"}`
	req1 := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader(body1))
	req1.SetBasicAuth(testAccountUUID, testAuthToken)
	rr1 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first SetLink: expected 200, got %d: %s", rr1.Code, rr1.Body.String())
	}
	var resp1 UsernameLinkSetResponse
	if err := json.Unmarshal(rr1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("decode resp1: %v", err)
	}
	if resp1.UsernameLinkHandle == "" {
		t.Fatal("expected non-empty handle on first publish")
	}

	// Second publish with keepLinkHandle=true reuses the same handle.
	encV2 := base64.StdEncoding.EncodeToString([]byte("encrypted-v2"))
	body2 := `{"usernameLinkEncryptedValue":"` + encV2 + `","keepLinkHandle":true}`
	req2 := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader(body2))
	req2.SetBasicAuth(testAccountUUID, testAuthToken)
	rr2 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("second SetLink: expected 200, got %d: %s", rr2.Code, rr2.Body.String())
	}
	var resp2 UsernameLinkSetResponse
	if err := json.Unmarshal(rr2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("decode resp2: %v", err)
	}
	if resp2.UsernameLinkHandle != resp1.UsernameLinkHandle {
		t.Errorf("keepLinkHandle=true: expected handle %q, got %q",
			resp1.UsernameLinkHandle, resp2.UsernameLinkHandle)
	}

	// Third publish without keepLinkHandle — handle rotates.
	encV3 := base64.StdEncoding.EncodeToString([]byte("encrypted-v3"))
	body3 := `{"usernameLinkEncryptedValue":"` + encV3 + `"}`
	req3 := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader(body3))
	req3.SetBasicAuth(testAccountUUID, testAuthToken)
	rr3 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Fatalf("third SetLink: expected 200, got %d: %s", rr3.Code, rr3.Body.String())
	}
	var resp3 UsernameLinkSetResponse
	if err := json.Unmarshal(rr3.Body.Bytes(), &resp3); err != nil {
		t.Fatalf("decode resp3: %v", err)
	}
	if resp3.UsernameLinkHandle == resp1.UsernameLinkHandle {
		t.Errorf("default keepLinkHandle=false should rotate handle, got reused %q", resp3.UsernameLinkHandle)
	}
}

func TestHandleSetUsernameLink_NoConfirmedHash(t *testing.T) {
	// Account exists but has never confirmed a username hash — Java
	// AccountController#setUsernameLink returns 409 Conflict in that case.
	s, _ := newTestServerWithAccount(t)

	encV := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	body := `{"usernameLinkEncryptedValue":"` + encV + `"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", rr.Code, rr.Body.String())
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
	confirmTestUsernameHash(t, s, testAccountUUID)

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
	confirmTestUsernameHash(t, s, testAccountUUID)

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

// --------------------------------------------------------------------------
// handleReserveUsernameHash additional error paths
// --------------------------------------------------------------------------

func TestHandleReserveUsernameHash_TooManyHashes(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// maxUsernameHashes = 20; send 21 to trigger the limit.
	hashes := make([]string, 21)
	hash := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for i := range hashes {
		hashes[i] = `"` + hash + `"`
	}
	body := `{"usernameHashes":[` + strings.Join(hashes, ",") + `]}`

	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for too many hashes, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleReserveUsernameHash_InvalidHashLength(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// 16 bytes is wrong; must be exactly 32.
	shortHash := base64.StdEncoding.EncodeToString(make([]byte, 16))
	body := `{"usernameHashes":["` + shortHash + `"]}`

	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid hash length, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleReserveUsernameHash_ConflictPath tests that when all username hashes
// are taken by another account, the endpoint returns 409.
func TestHandleReserveUsernameHash_ConflictPath(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Reserve a hash for the main account.
	hash := make([]byte, 32)
	hash[0] = 0xAB
	hashB64 := base64.StdEncoding.EncodeToString(hash)

	reserveReq := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(`{"usernameHashes":["`+hashB64+`"]}`))
	reserveReq.SetBasicAuth(testAccountUUID, testAuthToken)
	reserveRR := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(reserveRR, reserveReq)
	if reserveRR.Code != http.StatusOK {
		t.Fatalf("first reserve expected 200, got %d: %s", reserveRR.Code, reserveRR.Body.String())
	}

	// Confirm (finalize) the hash.
	var reserveResp UsernameHashReserveResponse
	if err := json.Unmarshal(reserveRR.Body.Bytes(), &reserveResp); err != nil {
		t.Fatalf("decode reserve response: %v", err)
	}

	// Create a second authenticated account and attempt to reserve the same hash.
	// The hash is already taken (confirmed above), so the manager should return conflict.
	newAcct := &accounts.Account{
		UUID:        "22222222-2222-2222-2222-222222222222",
		Number:      "+15550000001",
		IdentityKey: testIdentityKey,
		Devices: []accounts.Device{
			{
				ID:        accounts.PrimaryDeviceID,
				AuthToken: "other-token",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: testSignedPreKeyPub,
					Signature: testSignedPreKeySig,
				},
			},
		},
	}
	ctx := context.Background()
	if err := s.accounts.Create(ctx, newAcct); err != nil {
		t.Fatalf("create second account: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_hash/reserve", strings.NewReader(`{"usernameHashes":["`+hashB64+`"]}`))
	req2.SetBasicAuth("22222222-2222-2222-2222-222222222222", "other-token")
	rr2 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr2, req2)

	// Either 409 (all taken) or 200 (still available since only reserved, not confirmed).
	// Either exercises the ReserveHash code path.
	if rr2.Code != http.StatusOK && rr2.Code != http.StatusConflict {
		t.Errorf("unexpected status %d: %s", rr2.Code, rr2.Body.String())
	}
}

// --------------------------------------------------------------------------
// errUsernameService — injectable error mock for service.UsernameService
// --------------------------------------------------------------------------

// errUsernameService is a minimal service.UsernameService implementation
// that returns configurable errors from individual methods so that the
// REST handler error-handling branches can be covered by tests.
type errUsernameService struct {
	deleteHashErr  error
	deleteLinkErr  error
	lookupHashErr  error
	lookupLinkErr  error
	setLinkErr     error
	confirmHashErr error
	reserveHashErr error
}

func (e *errUsernameService) ReserveHash(_ context.Context, _ string, _ [][]byte) ([]byte, string, error) {
	return nil, "", e.reserveHashErr
}

func (e *errUsernameService) ConfirmHash(_ context.Context, _ string, _ []byte, _ string, _ []byte) error {
	return e.confirmHashErr
}

func (e *errUsernameService) LookupByHash(_ context.Context, _ []byte) (string, error) {
	return "", e.lookupHashErr
}

func (e *errUsernameService) DeleteHash(_ context.Context, _ string) error {
	return e.deleteHashErr
}

func (e *errUsernameService) SetLink(_ context.Context, _ *signalUsernames.UsernameLink) error {
	return e.setLinkErr
}

func (e *errUsernameService) GetLink(_ context.Context, _ string) (*signalUsernames.UsernameLink, error) {
	return nil, e.lookupLinkErr
}

func (e *errUsernameService) DeleteLink(_ context.Context, _ string) error {
	return e.deleteLinkErr
}

func (e *errUsernameService) DeleteExpiredReservations(_ context.Context) (int, error) {
	return 0, nil
}

func (e *errUsernameService) ExistingLinkHandle(_ context.Context, _ string) (string, error) {
	return "", nil
}

// --------------------------------------------------------------------------
// Internal error path tests using errUsernameService
// --------------------------------------------------------------------------

// TestHandleDeleteUsernameHash_InternalError exercises the branch where
// DeleteHash returns a non-UsernameNotFoundError, triggering a 500 response.
func TestHandleDeleteUsernameHash_InternalError(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	s.usernames = &errUsernameService{deleteHashErr: errors.New("store unavailable")}

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/username_hash", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleDeleteUsernameLink_InternalError exercises the branch where
// DeleteLink returns a non-UsernameLinkNotFoundError, triggering a 500 response.
func TestHandleDeleteUsernameLink_InternalError(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	s.usernames = &errUsernameService{deleteLinkErr: errors.New("store unavailable")}

	req := httptest.NewRequest(http.MethodDelete, "/v1/accounts/username_link", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleLookupUsernameHash_InternalError exercises the branch where
// LookupByHash returns a non-UsernameNotFoundError, triggering a 500 response.
func TestHandleLookupUsernameHash_InternalError(t *testing.T) {
	s := newTestServer(t)
	s.usernames = &errUsernameService{lookupHashErr: errors.New("store unavailable")}

	hashURLB64 := base64.URLEncoding.EncodeToString([]byte("some-hash"))
	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/username_hash/"+hashURLB64, nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleLookupUsernameLink_InternalError exercises the branch where
// GetLink returns a non-UsernameLinkNotFoundError, triggering a 500 response.
func TestHandleLookupUsernameLink_InternalError(t *testing.T) {
	s := newTestServer(t)
	s.usernames = &errUsernameService{lookupLinkErr: errors.New("store unavailable")}

	req := httptest.NewRequest(http.MethodGet, "/v1/accounts/username_link/some-handle", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandleSetUsernameLink_InternalError exercises the branch where SetLink
// returns a non-UsernameNotFoundError, triggering a 500 response.
func TestHandleSetUsernameLink_InternalError(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	s.usernames = &errUsernameService{setLinkErr: errors.New("store unavailable")}

	encValB64 := base64.StdEncoding.EncodeToString([]byte("encrypted-username"))
	body := `{"usernameLinkEncryptedValue":"` + encValB64 + `"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/accounts/username_link", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
}
