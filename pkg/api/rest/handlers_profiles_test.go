package rest

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
	"github.com/jeremyhahn/go-signal/pkg/service"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
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
	_, err := s.buildAvatarUploadAttributes(t.Context())
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
		SecretKey: secrets.MustNewSecureString(t.Context(), "TestSecretKey1234567890abcdefgh"),
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
		SecretKey: secrets.MustNewSecureString(t.Context(), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
	}

	attrs, err := s.buildAvatarUploadAttributes(t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The object name is random (Java parity), so assert the shape rather
	// than a fixed value — and assert it is not derived from the account.
	if !strings.HasPrefix(attrs.Key, "profiles/") {
		t.Errorf("expected a profiles/ prefixed key, got %q", attrs.Key)
	}
	if strings.Contains(attrs.Key, testAccountUUID) {
		t.Errorf("avatar object name must not embed the account UUID: %q", attrs.Key)
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

// --------------------------------------------------------------------------
// Avatar persistence (Java AvatarChange semantics)
// --------------------------------------------------------------------------

// setProfileWithAvatarFlags issues PUT /v1/profile for the test account and
// returns the recorder, so callers can assert both status and body.
func setProfileWithAvatarFlags(t *testing.T, s *Server, version string, avatar, sameAvatar bool) *httptest.ResponseRecorder {
	t.Helper()
	// Profile fields are encrypted blobs with exact byte sizes: name 81,
	// commitment 97 (the Java @ExactlySize constraints).
	body := fmt.Sprintf(`{"version":%q,"name":%q,"commitment":%q,"avatar":%t,"sameAvatar":%t}`,
		version,
		base64.StdEncoding.EncodeToString(make([]byte, 81)),
		base64.StdEncoding.EncodeToString(make([]byte, 97)),
		avatar, sameAvatar)
	req := httptest.NewRequest(http.MethodPut, "/v1/profile", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	return rr
}

// A new upload must store the same object name the upload form is signed for,
// otherwise the client uploads to a key the server cannot serve back.
func TestSetProfile_AvatarUploadPersistsTheSignedKey(t *testing.T) {
	s, _ := newTestServerWithAvatarCDN(t)

	rr := setProfileWithAvatarFlags(t, s, "v1", true, false)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var attrs ProfileAvatarUploadAttributes
	if err := json.Unmarshal(rr.Body.Bytes(), &attrs); err != nil {
		t.Fatalf("unmarshal upload attributes: %v", err)
	}
	if attrs.Key == "" {
		t.Fatal("upload attributes carry no key")
	}

	stored, err := s.profiles.Get(context.Background(), testAccountUUID, "v1")
	if err != nil {
		t.Fatalf("get stored profile: %v", err)
	}
	if stored.Avatar != attrs.Key {
		t.Errorf("stored avatar = %q, want the signed key %q", stored.Avatar, attrs.Key)
	}
}

// The UNCHANGED case: {avatar:true, sameAvatar:true} at the version that
// already holds the avatar keeps it. Both flags are required — Java's
// CreateProfileRequest.getAvatarChange reads `avatar` first, so sameAvatar
// alone is CLEAR, not UNCHANGED (TestSetProfile_SameAvatarWithoutAvatarClears).
//
// The version is the one being written, matching
// ProfileController.setProfile's profilesManager.get(uuid, request.version()).
// A Signal profile version is a function of the profile key, so a client that
// only edits its name reuses it and lands here.
func TestSetProfile_SameAvatarKeepsThisVersionsKey(t *testing.T) {
	s, _ := newTestServerWithAvatarCDN(t)

	rr := setProfileWithAvatarFlags(t, s, "v1", true, false)
	if rr.Code != http.StatusOK {
		t.Fatalf("first set: expected 200, got %d", rr.Code)
	}
	var attrs ProfileAvatarUploadAttributes
	if err := json.Unmarshal(rr.Body.Bytes(), &attrs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if rr := setProfileWithAvatarFlags(t, s, "v1", true, true); rr.Code != http.StatusOK {
		t.Fatalf("sameAvatar set: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	stored, err := s.profiles.Get(context.Background(), testAccountUUID, "v1")
	if err != nil {
		t.Fatalf("get stored profile: %v", err)
	}
	if stored.Avatar != attrs.Key {
		t.Errorf("sameAvatar stored %q, want the previous key %q", stored.Avatar, attrs.Key)
	}
}

// {avatar:false, sameAvatar:true} is CLEAR, not UNCHANGED. Java decides on
// `avatar` before it ever looks at sameAvatar, so a client that asks for no
// avatar gets none whatever else it sends. Resolving sameAvatar first instead
// keeps the avatar of a request that asked to drop it.
func TestSetProfile_SameAvatarWithoutAvatarClears(t *testing.T) {
	s, _ := newTestServerWithAvatarCDN(t)

	if rr := setProfileWithAvatarFlags(t, s, "v1", true, false); rr.Code != http.StatusOK {
		t.Fatalf("first set: expected 200, got %d", rr.Code)
	}
	if rr := setProfileWithAvatarFlags(t, s, "v1", false, true); rr.Code != http.StatusOK {
		t.Fatalf("clear set: expected 200, got %d", rr.Code)
	}

	stored, err := s.profiles.Get(context.Background(), testAccountUUID, "v1")
	if err != nil {
		t.Fatalf("get stored profile: %v", err)
	}
	if stored.Avatar != "" {
		t.Errorf("avatar = %q, want it cleared", stored.Avatar)
	}
}

// UNCHANGED resolves against the version being written, so a version that
// carries no avatar yet has nothing to keep — even when another version does.
// A profile version changes only when the profile key rotates, and an avatar
// encrypted under the old key is not one the new version can serve.
func TestSetProfile_SameAvatarAtANewVersionKeepsNothing(t *testing.T) {
	s, _ := newTestServerWithAvatarCDN(t)

	if rr := setProfileWithAvatarFlags(t, s, "v1", true, false); rr.Code != http.StatusOK {
		t.Fatalf("first set: expected 200, got %d", rr.Code)
	}
	if rr := setProfileWithAvatarFlags(t, s, "v2", true, true); rr.Code != http.StatusOK {
		t.Fatalf("sameAvatar at a new version: expected 200, got %d", rr.Code)
	}

	stored, err := s.profiles.Get(context.Background(), testAccountUUID, "v2")
	if err != nil {
		t.Fatalf("get stored profile: %v", err)
	}
	if stored.Avatar != "" {
		t.Errorf("v2 avatar = %q, want empty: v2 never had one", stored.Avatar)
	}
}

// Only a key this server issued is carried forward. Java applies the same
// startsWith("profiles/") filter, and the prefix has one definition
// (avatarObjectPrefix) shared with the generator so the two cannot drift.
func TestSetProfile_SameAvatarIgnoresAKeyOutsideTheProfilesPrefix(t *testing.T) {
	s, _ := newTestServerWithAvatarCDN(t)

	seeded := &profiles.Profile{
		UUID:       testAccountUUID,
		Version:    "v1",
		Name:       make([]byte, 81),
		Commitment: make([]byte, 97),
		Avatar:     "../../etc/passwd",
	}
	if err := s.profiles.Set(context.Background(), seeded); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	if rr := setProfileWithAvatarFlags(t, s, "v1", true, true); rr.Code != http.StatusOK {
		t.Fatalf("sameAvatar set: expected 200, got %d", rr.Code)
	}

	stored, err := s.profiles.Get(context.Background(), testAccountUUID, "v1")
	if err != nil {
		t.Fatalf("get stored profile: %v", err)
	}
	if stored.Avatar != "" {
		t.Errorf("avatar = %q, want empty: it is not under %q", stored.Avatar, avatarObjectPrefix)
	}
}

// gatedProfileService holds a request inside ProfileService.Get so a test can
// stop it between the sameAvatar read and the write that follows — the
// read-modify-write window. It delegates to the real service, so both requests
// run production code end to end; only the scheduling is forced.
//
// The gate is armed explicitly rather than firing on the first Get: the test's
// own assertions and the GET handler call Get too, and a gate that triggers on
// whichever call happens to arrive first would close on the wrong one.
type gatedProfileService struct {
	service.ProfileService
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (g *gatedProfileService) Get(ctx context.Context, uuid, version string) (*profiles.Profile, error) {
	p, err := g.ProfileService.Get(ctx, uuid, version)
	g.hold()
	return p, err
}

// GetLatest is gated too, and deliberately: it is the read this path used to
// perform. A gate on Get alone would let a regression to GetLatest slip past
// the read unheld, and the test would then fail on "never reached its read"
// instead of on the key it wrote — red either way, but naming the wrong thing.
func (g *gatedProfileService) GetLatest(ctx context.Context, uuid string) (*profiles.Profile, error) {
	p, err := g.ProfileService.GetLatest(ctx, uuid)
	g.hold()
	return p, err
}

func (g *gatedProfileService) hold() {
	if g.armed.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.release
	}
}

// A sameAvatar request paused between its read and its write must still write
// its OWN version's key. Reading the latest version instead made it adopt
// whatever version happened to be latest at the instant it read — so a
// concurrent upload at another version would be copied onto this one.
//
// What this does NOT establish: the two requests remain a read-modify-write
// with no compare-and-swap, so which of them ends up as the account's latest
// marker is still decided by write order. Closing that needs an atomic
// primitive pkg/store.KVClient does not have; it is tracked separately.
func TestSetProfile_ConcurrentSameAvatarKeepsItsOwnVersionsKey(t *testing.T) {
	s, _ := newTestServerWithAvatarCDN(t)

	rr := setProfileWithAvatarFlags(t, s, "v1", true, false)
	if rr.Code != http.StatusOK {
		t.Fatalf("seed v1: expected 200, got %d", rr.Code)
	}
	var v1Attrs ProfileAvatarUploadAttributes
	if err := json.Unmarshal(rr.Body.Bytes(), &v1Attrs); err != nil {
		t.Fatalf("unmarshal v1: %v", err)
	}

	if rr := setProfileWithAvatarFlags(t, s, "v2", true, false); rr.Code != http.StatusOK {
		t.Fatalf("seed v2: expected 200, got %d", rr.Code)
	}

	gate := &gatedProfileService{
		ProfileService: s.profiles,
		entered:        make(chan struct{}),
		release:        make(chan struct{}),
	}
	s.profiles = gate
	gate.armed.Store(true)

	// A: keep v1's avatar. It reads, then parks inside the gate.
	aDone := make(chan int, 1)
	go func() { aDone <- setProfileWithAvatarFlags(t, s, "v1", true, true).Code }()

	select {
	case <-gate.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("request A never reached its sameAvatar read")
	}

	// B: a fresh upload at v2, committed while A is parked. It resolves
	// avatarUpdate, so it takes no Get and the gate does not hold it.
	rr = setProfileWithAvatarFlags(t, s, "v2", true, false)
	if rr.Code != http.StatusOK {
		t.Fatalf("request B: expected 200, got %d", rr.Code)
	}
	var v2Attrs ProfileAvatarUploadAttributes
	if err := json.Unmarshal(rr.Body.Bytes(), &v2Attrs); err != nil {
		t.Fatalf("unmarshal v2: %v", err)
	}

	close(gate.release)
	select {
	case code := <-aDone:
		if code != http.StatusOK {
			t.Fatalf("request A: expected 200, got %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("request A never completed after release")
	}

	storedV1, err := s.profiles.Get(context.Background(), testAccountUUID, "v1")
	if err != nil {
		t.Fatalf("get v1: %v", err)
	}
	if storedV1.Avatar != v1Attrs.Key {
		t.Errorf("v1 avatar = %q, want its own key %q (adopting another version's key is the defect)",
			storedV1.Avatar, v1Attrs.Key)
	}
	if storedV1.Avatar == v2Attrs.Key {
		t.Errorf("v1 adopted v2's key %q", v2Attrs.Key)
	}

	storedV2, err := s.profiles.Get(context.Background(), testAccountUUID, "v2")
	if err != nil {
		t.Fatalf("get v2: %v", err)
	}
	if storedV2.Avatar != v2Attrs.Key {
		t.Errorf("v2 avatar = %q, want the key its own upload was signed for %q", storedV2.Avatar, v2Attrs.Key)
	}
}

func TestSetProfile_NoAvatarClearsTheKey(t *testing.T) {
	s, _ := newTestServerWithAvatarCDN(t)

	if rr := setProfileWithAvatarFlags(t, s, "v1", true, false); rr.Code != http.StatusOK {
		t.Fatalf("first set: expected 200, got %d", rr.Code)
	}
	if rr := setProfileWithAvatarFlags(t, s, "v2", false, false); rr.Code != http.StatusOK {
		t.Fatalf("clear set: expected 200, got %d", rr.Code)
	}

	stored, err := s.profiles.Get(context.Background(), testAccountUUID, "v2")
	if err != nil {
		t.Fatalf("get stored profile: %v", err)
	}
	if stored.Avatar != "" {
		t.Errorf("avatar should be cleared, got %q", stored.Avatar)
	}
}

// Two uploads must not reuse an object name — a deterministic name derived
// from the account would make every user's avatar object guessable.
func TestBuildAvatarUploadAttributes_KeysAreUnique(t *testing.T) {
	s := newTestServer(t)
	s.avatarCDN = AvatarCDNConfig{
		Bucket:    "my-bucket",
		Region:    "eu-west-1",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: secrets.MustNewSecureString(t.Context(), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
	}

	first, err := s.buildAvatarUploadAttributes(t.Context())
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := s.buildAvatarUploadAttributes(t.Context())
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.Key == second.Key {
		t.Errorf("two uploads produced the same object name %q", first.Key)
	}
}

// failingGetStore wraps a real store and makes Get fail with an error that is
// NOT "not found" — a database outage, a cancelled context, an unreadable row.
// Set still works, so a handler that ignored the read error would visibly
// persist the wrong thing.
type failingGetStore struct {
	profiles.ProfileStore
	err error
}

func (f *failingGetStore) Get(context.Context, string, string) (*profiles.Profile, error) {
	return nil, f.err
}

// TestSetProfile_SameAvatarFailsClosedWhenThePreviousReadFails is the
// regression test for a fail-open in the sameAvatar path: every read error
// was collapsed into an empty avatar key, which the handler then persisted
// while returning 200. A request that explicitly asked to KEEP its avatar
// would delete it during a transient backend failure, and report success for
// doing so.
//
// Reverting previousAvatarKey to swallow the error makes this fail: the
// response becomes 200 and the stored avatar becomes "".
func TestSetProfile_SameAvatarFailsClosedWhenThePreviousReadFails(t *testing.T) {
	s, _ := newTestServerWithAvatarCDN(t)

	// Establish a real avatar first, through the working store.
	rr := setProfileWithAvatarFlags(t, s, "v1", true, false)
	if rr.Code != http.StatusOK {
		t.Fatalf("first set: expected 200, got %d", rr.Code)
	}
	var attrs ProfileAvatarUploadAttributes
	if err := json.Unmarshal(rr.Body.Bytes(), &attrs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Now make the previous-avatar read fail.
	backing := memory.NewMemoryProfileStore()
	if err := backing.Set(context.Background(), &profiles.Profile{
		UUID: testAccountUUID, Version: "v1", Avatar: attrs.Key,
	}); err != nil {
		t.Fatalf("seed backing store: %v", err)
	}
	failing := &failingGetStore{
		ProfileStore: backing,
		err:          errors.New("database is unavailable"),
	}
	s.profiles = profiles.NewProfilesManager(failing)

	rr = setProfileWithAvatarFlags(t, s, "v1", true, true)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when the previous avatar cannot be read, got %d: %s",
			rr.Code, rr.Body.String())
	}

	// And nothing was overwritten: a failed read must not become a successful
	// write that clears the avatar.
	stored, err := backing.Get(context.Background(), testAccountUUID, "v1")
	if err != nil {
		t.Fatalf("the seeded profile disappeared: %v", err)
	}
	if stored.Avatar != attrs.Key {
		t.Errorf("stored avatar = %q, want it untouched at %q", stored.Avatar, attrs.Key)
	}
}

// A genuinely absent previous profile is not an error — sameAvatar on an
// account with no profile yet resolves to no avatar and still succeeds.
func TestSetProfile_SameAvatarWithNoPreviousProfileSucceeds(t *testing.T) {
	s, _ := newTestServerWithAvatarCDN(t)

	rr := setProfileWithAvatarFlags(t, s, "v1", true, true)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	stored, err := s.profiles.Get(context.Background(), testAccountUUID, "v1")
	if err != nil {
		t.Fatalf("get stored profile: %v", err)
	}
	if stored.Avatar != "" {
		t.Errorf("avatar = %q, want empty", stored.Avatar)
	}
}
