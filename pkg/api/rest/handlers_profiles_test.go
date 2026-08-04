package rest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
)

// validProfileCredentialRequest produces a hex-encoded, wire-valid
// ProfileKeyCredentialRequest for the given ACI together with the matching
// serialized ProfileKeyCommitment, so credential-handler tests can exercise the
// real deserialize path.
func validProfileCredentialRequest(t *testing.T, aciUUID string) (reqHex string, commitment []byte) {
	t.Helper()
	var rnd zkgroup.RandomnessBytes
	for i := range rnd {
		rnd[i] = byte(i + 1)
	}
	serverSecret, err := zkgroup.GenerateServerSecretParams(rnd)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverSecret.GetPublicParams()

	parsed, err := uuid.Parse(aciUUID)
	if err != nil {
		t.Fatalf("parse aci: %v", err)
	}
	var aciBytes [16]byte
	copy(aciBytes[:], parsed[:])
	aci := zkgroup.NewACI(aciBytes)

	var pk zkgroup.ProfileKeyBytes
	for i := range pk {
		pk[i] = byte(i + 2)
	}
	profileKey := zkgroup.NewProfileKey(pk)

	var reqRnd zkgroup.RandomnessBytes
	for i := range reqRnd {
		reqRnd[i] = byte(i + 20)
	}
	ctx, err := serverPublic.CreateProfileKeyCredentialRequestContext(reqRnd, aci, profileKey)
	if err != nil {
		t.Fatalf("CreateProfileKeyCredentialRequestContext: %v", err)
	}
	reqBytes := zkgroup.SerializeProfileKeyCredentialRequest(ctx.GetRequest())
	commitBytes := zkgroup.SerializeProfileKeyCommitment(profileKey.GetCommitment(aci))
	return hex.EncodeToString(reqBytes), commitBytes
}

// --------------------------------------------------------------------------
// handleSetProfile
// --------------------------------------------------------------------------

func TestHandleSetProfile_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Profile fields are encrypted blobs with exact byte sizes (matching the
	// Java @ExactlySize constraints): name 81/285, about 156/282/540,
	// aboutEmoji 60, commitment 97.
	nameB64 := base64.StdEncoding.EncodeToString(make([]byte, 81))
	aboutB64 := base64.StdEncoding.EncodeToString(make([]byte, 156))
	aboutEmojiB64 := base64.StdEncoding.EncodeToString(make([]byte, 60))
	commitB64 := base64.StdEncoding.EncodeToString(make([]byte, 97))

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

	reqHex, commitment := validProfileCredentialRequest(t, testAccountUUID)
	p := &profiles.Profile{
		UUID:       testAccountUUID,
		Version:    "v1",
		Commitment: commitment,
	}
	if err := s.profiles.Set(context.Background(), p); err != nil {
		t.Fatalf("failed to set profile: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v1/"+reqHex, nil)
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

func TestHandleGetProfileWithCredential_InvalidRequest(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// A non-deserializable credential request is rejected with 400.
	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v1/abcdef", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGetProfileWithCredential_AccountNotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// A wire-valid request but for a UUID that does not exist resolves to 404.
	reqHex, _ := validProfileCredentialRequest(t, "99999999-9999-9999-9999-999999999999")
	req := httptest.NewRequest(http.MethodGet, "/v1/profile/99999999-9999-9999-9999-999999999999/v1/"+reqHex, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

func TestHandleGetProfileWithCredential_ProfileNotFound(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Without a stored profile (and thus no commitment) a credential cannot be
	// issued — the endpoint returns 404.
	reqHex, _ := validProfileCredentialRequest(t, testAccountUUID)
	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v99/"+reqHex, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
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

// --------------------------------------------------------------------------
// avatarCDNNotConfiguredError / buildAvatarUploadAttributes
// --------------------------------------------------------------------------

func TestAvatarCDNNotConfiguredError_Error(t *testing.T) {
	e := &avatarCDNNotConfiguredError{}
	got := e.Error()
	if got != "avatar CDN not configured" {
		t.Errorf("unexpected error string: %q", got)
	}
}

// TestHandleSetProfile_AvatarUploadNoCDN verifies that requesting an avatar
// upload when no CDN is configured returns 503. This exercises both
// buildAvatarUploadAttributes and avatarCDNNotConfiguredError.Error().
func TestHandleSetProfile_AvatarUploadNoCDN(t *testing.T) {
	// The default test server has no AvatarCDN configured, so
	// buildAvatarUploadAttributes will return errAvatarCDNNotConfigured.
	s, _ := newTestServerWithAccount(t)

	nameB64 := base64.StdEncoding.EncodeToString(make([]byte, 81))
	commitB64 := base64.StdEncoding.EncodeToString(make([]byte, 97))

	body := `{
		"version": "v1",
		"name": "` + nameB64 + `",
		"commitment": "` + commitB64 + `",
		"avatar": true,
		"sameAvatar": false
	}`
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when CDN is not configured, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestBuildAvatarUploadAttributes_NoCDN calls buildAvatarUploadAttributes
// directly on a server without CDN configuration.
func TestBuildAvatarUploadAttributes_NoCDN(t *testing.T) {
	s := newTestServer(t)
	_, err := s.buildAvatarUploadAttributes("some-uuid")
	if err == nil {
		t.Fatal("expected error when CDN not configured")
	}
	if err.Error() != "avatar CDN not configured" {
		t.Errorf("unexpected error: %v", err)
	}
}

// newTestServerWithAvatarCDN creates a test server whose AvatarCDN is
// configured with dummy (but non-empty) credentials so that
// buildAvatarUploadAttributes takes the success path.
func newTestServerWithAvatarCDN(t *testing.T) (*Server, *accounts.Account) {
	t.Helper()

	s, transport := newTestServerWithVerification(t)

	// Patch the avatarCDN field directly — the struct is unexported but we are
	// in the same package (test file is package rest).
	s.avatarCDN = AvatarCDNConfig{
		Bucket:    "test-bucket",
		Region:    "us-east-1",
		AccessKey: "AKIATESTKEY",
		SecretKey: "TestSecretKey1234567890abcdefgh",
	}

	acct := testAccount()
	if err := s.accounts.Create(context.Background(), acct); err != nil {
		t.Fatalf("failed to create test account: %v", err)
	}

	_ = transport
	return s, acct
}

// TestHandleSetProfile_AvatarUploadWithCDN verifies the happy path for avatar
// upload when CDN credentials are configured: the handler returns 200 with an
// S3 POST-policy body.
func TestHandleSetProfile_AvatarUploadWithCDN(t *testing.T) {
	s, _ := newTestServerWithAvatarCDN(t)

	nameB64 := base64.StdEncoding.EncodeToString(make([]byte, 81))
	commitB64 := base64.StdEncoding.EncodeToString(make([]byte, 97))

	body := `{
		"version": "v1",
		"name": "` + nameB64 + `",
		"commitment": "` + commitB64 + `",
		"avatar": true,
		"sameAvatar": false
	}`
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 when CDN is configured, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp ProfileAvatarUploadAttributes
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.Key == "" {
		t.Error("expected non-empty avatar key")
	}
	if resp.Credential == "" {
		t.Error("expected non-empty credential")
	}
	if resp.Signature == "" {
		t.Error("expected non-empty signature")
	}
}

// TestBuildAvatarUploadAttributes_WithCDN calls buildAvatarUploadAttributes
// directly on a server with CDN configuration to exercise the signing path.
func TestBuildAvatarUploadAttributes_WithCDN(t *testing.T) {
	s := newTestServer(t)
	s.avatarCDN = AvatarCDNConfig{
		Bucket:    "my-bucket",
		Region:    "eu-west-1",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	attrs, err := s.buildAvatarUploadAttributes("test-uuid-1234")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attrs.Key != "profiles/test-uuid-1234" {
		t.Errorf("expected key profiles/test-uuid-1234, got %q", attrs.Key)
	}
	if attrs.Algorithm != "AWS4-HMAC-SHA256" {
		t.Errorf("expected AWS4-HMAC-SHA256 algorithm, got %q", attrs.Algorithm)
	}
	if attrs.ACL != "private" {
		t.Errorf("expected private ACL, got %q", attrs.ACL)
	}
	if attrs.Policy == "" {
		t.Error("expected non-empty policy")
	}
	if attrs.Signature == "" {
		t.Error("expected non-empty signature")
	}
}
