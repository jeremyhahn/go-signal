package rest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/profiles"
)

// --------------------------------------------------------------------------
// handleSetProfile
// --------------------------------------------------------------------------

func TestHandleSetProfile_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	nameB64 := base64.StdEncoding.EncodeToString([]byte("Test User"))
	aboutB64 := base64.StdEncoding.EncodeToString([]byte("About me"))
	aboutEmojiB64 := base64.StdEncoding.EncodeToString([]byte("emoji"))
	commitB64 := base64.StdEncoding.EncodeToString([]byte("commitment"))

	body := `{
		"version": "v1",
		"name": "` + nameB64 + `",
		"about": "` + aboutB64 + `",
		"aboutEmoji": "` + aboutEmojiB64 + `",
		"commitment": "` + commitB64 + `"
	}`

	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleSetProfile_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSetProfile_InvalidNameBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"version":"v1","name":"!!!not-base64!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSetProfile_InvalidAboutBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"version":"v1","about":"!!!not-base64!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSetProfile_InvalidAboutEmojiBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"version":"v1","aboutEmoji":"!!!not-base64!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSetProfile_InvalidPaymentAddressBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"version":"v1","paymentAddress":"!!!not-base64!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSetProfile_InvalidCommitmentBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"version":"v1","commitment":"!!!not-base64!!!"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleSetProfile_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetProfile (latest)
// --------------------------------------------------------------------------

func TestHandleGetProfile_WithProfile(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Set a profile first.
	p := &profiles.Profile{
		UUID:    testAccountUUID,
		Version: "v1",
		Name:    []byte("Test"),
	}
	if err := s.profiles.Set(context.Background(), p); err != nil {
		t.Fatalf("failed to set profile: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ProfileResponseEntity
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.UUID != testAccountUUID {
		t.Errorf("expected UUID %s, got %s", testAccountUUID, resp.UUID)
	}
	if resp.Name == "" {
		t.Error("expected non-empty name")
	}
}

func TestHandleGetProfile_NoProfile(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Should return minimal profile with account info.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ProfileResponseEntity
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.UUID != testAccountUUID {
		t.Errorf("expected UUID %s, got %s", testAccountUUID, resp.UUID)
	}
}

func TestHandleGetProfile_AccountNotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Authenticate as the test account but request a profile for a
	// different UUID that does not exist in the store.
	req := httptest.NewRequest(http.MethodGet, "/v1/profile/99999999-9999-9999-9999-999999999999", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleGetProfile_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID, nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetVersionedProfile
// --------------------------------------------------------------------------

func TestHandleGetVersionedProfile_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	p := &profiles.Profile{
		UUID:    testAccountUUID,
		Version: "v2",
		Name:    []byte("Versioned Name"),
		About:   []byte("Versioned about"),
	}
	if err := s.profiles.Set(context.Background(), p); err != nil {
		t.Fatalf("failed to set profile: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v2", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetVersionedProfile_NotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// When no profile exists for a version, the server returns a minimal 200
	// response with account-level fields (matching Java server behavior).
	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v99", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleGetVersionedProfile_AccountNotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Authenticate as the test account but request a profile for a
	// different UUID that does not exist in the store.
	req := httptest.NewRequest(http.MethodGet, "/v1/profile/99999999-9999-9999-9999-999999999999/v1", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleGetVersionedProfile_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v1", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetProfileWithCredential
// --------------------------------------------------------------------------

func TestHandleGetProfileWithCredential_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	p := &profiles.Profile{
		UUID:    testAccountUUID,
		Version: "v1",
		Name:    []byte("Name"),
	}
	if err := s.profiles.Set(context.Background(), p); err != nil {
		t.Fatalf("failed to set profile: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v1/abcdef", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ProfileResponseEntity
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Credential == nil {
		t.Error("expected non-nil credential")
	}
}

func TestHandleGetProfileWithCredential_AccountNotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Authenticate as the test account but request a profile for a
	// different UUID that does not exist in the store.
	req := httptest.NewRequest(http.MethodGet, "/v1/profile/99999999-9999-9999-9999-999999999999/v1/abcdef", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleGetProfileWithCredential_ProfileNotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// When no profile exists, the server returns a minimal 200 response with
	// account-level fields and a stub credential.
	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v99/abcdef", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestHandleGetProfileWithCredential_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v1/abcdef", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleBatchIdentityCheck
// --------------------------------------------------------------------------

func TestHandleBatchIdentityCheck_NoMismatches(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Compute correct fingerprint (first 4 bytes of SHA-256 of identity key).
	hash := sha256.Sum256(testIdentityKey)
	fp := base64.StdEncoding.EncodeToString(hash[:4])

	body := `{"elements":[{"uuid":"` + testAccountUUID + `","fingerprint":"` + fp + `"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/profile/identity_check/batch", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp BatchIdentityCheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.Elements) != 0 {
		t.Errorf("expected 0 mismatches, got %d", len(resp.Elements))
	}
}

func TestHandleBatchIdentityCheck_WithMismatch(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	wrongFp := base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	body := `{"elements":[{"uuid":"` + testAccountUUID + `","fingerprint":"` + wrongFp + `"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/profile/identity_check/batch", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp BatchIdentityCheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if len(resp.Elements) != 1 {
		t.Fatalf("expected 1 mismatch, got %d", len(resp.Elements))
	}
}

func TestHandleBatchIdentityCheck_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/profile/identity_check/batch", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleBatchIdentityCheck_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/profile/identity_check/batch", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleBatchIdentityCheck_UnknownUUID(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	wrongFp := base64.StdEncoding.EncodeToString([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	body := `{"elements":[{"uuid":"unknown-uuid","fingerprint":"` + wrongFp + `"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/profile/identity_check/batch", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp BatchIdentityCheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	// Unknown UUIDs should be silently skipped.
	if len(resp.Elements) != 0 {
		t.Errorf("expected 0 mismatches for unknown UUID, got %d", len(resp.Elements))
	}
}

func TestHandleBatchIdentityCheck_InvalidFingerprintBase64(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"elements":[{"uuid":"` + testAccountUUID + `","fingerprint":"!!!"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/profile/identity_check/batch", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	// Invalid base64 fingerprints should be skipped, not cause error.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// fingerprintEqual
// --------------------------------------------------------------------------

func TestFingerprintEqual_IdenticalSlices(t *testing.T) {
	a := []byte{0x01, 0x02, 0x03, 0x04}
	if !fingerprintEqual(a, a) {
		t.Error("expected equal")
	}
}

func TestFingerprintEqual_DifferentSlices(t *testing.T) {
	a := []byte{0x01, 0x02}
	b := []byte{0x01, 0x03}
	if fingerprintEqual(a, b) {
		t.Error("expected not equal")
	}
}

func TestFingerprintEqual_EmptySlice(t *testing.T) {
	if fingerprintEqual([]byte{}, []byte{0x01}) {
		t.Error("expected not equal for empty slice")
	}
}

func TestFingerprintEqual_BothEmpty(t *testing.T) {
	if fingerprintEqual([]byte{}, []byte{}) {
		t.Error("expected not equal for both empty")
	}
}

// TestFingerprintEqual_ShorterSubmitted verifies that a submitted fingerprint
// that is a prefix of the stored fingerprint is rejected. The old code accepted
// this case (prefix-match bug); the fixed implementation requires exact length
// equality to prevent an oracle attack where a 1-byte guess matches 1/256 of
// all stored 4-byte fingerprints.
func TestFingerprintEqual_ShorterSubmitted(t *testing.T) {
	a := []byte{0x01, 0x02}
	b := []byte{0x01, 0x02, 0x03, 0x04}
	if fingerprintEqual(a, b) {
		t.Error("submitted prefix must NOT match longer stored fingerprint (prefix-match bug fix)")
	}
}

// --------------------------------------------------------------------------
// buildProfileResponse
// --------------------------------------------------------------------------

func TestBuildProfileResponse_WithNilProfile(t *testing.T) {
	acct := testAccount()
	resp := buildProfileResponse(acct, nil)
	if resp.UUID != acct.UUID {
		t.Errorf("expected UUID %s, got %s", acct.UUID, resp.UUID)
	}
	if resp.Name != "" {
		t.Error("expected empty name for nil profile")
	}
}

func TestBuildProfileResponse_WithProfile(t *testing.T) {
	acct := testAccount()
	p := &profiles.Profile{
		UUID:           acct.UUID,
		Version:        "v1",
		Name:           []byte("Test"),
		About:          []byte("About"),
		AboutEmoji:     []byte("emoji"),
		PaymentAddress: []byte("addr"),
		Avatar:         "avatar-url",
	}
	resp := buildProfileResponse(acct, p)
	if resp.Name == "" {
		t.Error("expected non-empty name")
	}
	if resp.About == "" {
		t.Error("expected non-empty about")
	}
	if resp.Avatar != "avatar-url" {
		t.Errorf("expected avatar-url, got %s", resp.Avatar)
	}
}
