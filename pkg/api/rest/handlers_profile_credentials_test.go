package rest

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-signal/pkg/certificates"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
	"github.com/jeremyhahn/go-signal/pkg/service"
)

// errCert is a sentinel error returned by the stub certificate service.
var errCert = errors.New("certificate service error")

// stubCertificateService implements service.CertificateService with a
// configurable GetExpiringProfileKeyCredential response.
type stubCertificateService struct {
	credentialErr error // if set, returned by GetExpiringProfileKeyCredential
}

func (s *stubCertificateService) GetDeliveryCertificate(_ context.Context, _, _ string, _ uint32, _ []byte, _ bool) (*certificates.DeliveryCertificate, error) {
	return nil, nil
}

func (s *stubCertificateService) GetGroupCredentials(_ context.Context, _, _ string, _, _ int64) (*certificates.GroupCredentials, error) {
	return nil, nil
}

func (s *stubCertificateService) GetExpiringProfileKeyCredential(_ context.Context, _ string, _ *zkgroup.ProfileKeyCredentialRequest, _ *zkgroup.ProfileKeyCommitment, _ zkgroup.Timestamp) (*certificates.ExpiringProfileKeyCredentialResponse, error) {
	return nil, s.credentialErr
}

func (s *stubCertificateService) GetExpiringProfileKeyCredentialStub(_ context.Context, _ string, _ zkgroup.Timestamp) (*certificates.ExpiringProfileKeyCredentialResponse, error) {
	return nil, nil
}

// compile-time interface check.
var _ service.CertificateService = (*stubCertificateService)(nil)

// --------------------------------------------------------------------------
// handleGetProfileWithCredential — missing identifier → 400
// --------------------------------------------------------------------------

func TestHandleGetProfileWithCredential_MissingIdentifierReturns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// No PathValue set for "identifier"; r.PathValue("identifier") returns "".
	req := httptest.NewRequest(http.MethodGet, "/v1/profile///v1/deadbeef", nil)
	rr := httptest.NewRecorder()
	s.handleGetProfileWithCredential(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing identifier, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetProfileWithCredential — missing credential request → 400
// --------------------------------------------------------------------------

func TestHandleGetProfileWithCredential_MissingCredentialRequestReturns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v1/", nil)
	req.SetPathValue("identifier", testAccountUUID)
	req.SetPathValue("version", "v1")
	// "credentialRequest" PathValue left unset → returns "".
	rr := httptest.NewRecorder()
	s.handleGetProfileWithCredential(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing credentialRequest, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetProfileWithCredential — invalid hex encoding in credential request → 400
// --------------------------------------------------------------------------

func TestHandleGetProfileWithCredential_InvalidHexEncodingReturns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// "XXXX" is not valid hex (X is not a hex digit).
	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v1/XXXX", nil)
	req.SetPathValue("identifier", testAccountUUID)
	req.SetPathValue("version", "v1")
	req.SetPathValue("credentialRequest", "XXXX")
	rr := httptest.NewRecorder()
	s.handleGetProfileWithCredential(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid hex encoding, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetProfileWithCredential — invalid profile version → 400
// --------------------------------------------------------------------------

func TestHandleGetProfileWithCredential_InvalidVersionReturns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/profile/"+testAccountUUID+"/v!/deadbeef", nil)
	req.SetPathValue("identifier", testAccountUUID)
	req.SetPathValue("version", "v!invalid") // contains '!' which isValidProfileVersion rejects
	req.SetPathValue("credentialRequest", "deadbeef")
	rr := httptest.NewRecorder()
	s.handleGetProfileWithCredential(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid version, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetProfileWithCredential — malformed stored commitment → 500
// --------------------------------------------------------------------------

func TestHandleGetProfileWithCredential_MalformedCommitmentReturns500(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	reqHex, _ := validProfileCredentialRequest(t, testAccountUUID)

	// Store a profile with a non-empty but malformed commitment (wrong length).
	if err := s.profiles.Set(context.Background(), &profiles.Profile{
		UUID:       testAccountUUID,
		Version:    "v1",
		Commitment: []byte{0x01}, // 1 byte — far too short for a valid commitment
	}); err != nil {
		t.Fatalf("set profile: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/v1/profile/"+testAccountUUID+"/v1/"+reqHex, nil)
	req.SetPathValue("identifier", testAccountUUID)
	req.SetPathValue("version", "v1")
	req.SetPathValue("credentialRequest", reqHex)
	rr := httptest.NewRecorder()
	// Drive through the full HTTP stack so auth middleware populates the account.
	req2 := httptest.NewRequest(http.MethodGet,
		"/v1/profile/"+testAccountUUID+"/v1/"+reqHex, nil)
	req2.SetBasicAuth(testAccountUUID, testAuthToken)
	rr2 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for malformed commitment, got %d: %s", rr2.Code, rr2.Body.String())
	}
	_ = rr
}

// --------------------------------------------------------------------------
// handleGetProfileWithCredential — ZKGroupError from issuance → 400
// --------------------------------------------------------------------------

func TestHandleGetProfileWithCredential_ZKGroupErrorReturns400(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	reqHex, commitment := validProfileCredentialRequest(t, testAccountUUID)
	if err := s.profiles.Set(context.Background(), &profiles.Profile{
		UUID:       testAccountUUID,
		Version:    "v1",
		Commitment: commitment,
	}); err != nil {
		t.Fatalf("set profile: %v", err)
	}

	// Replace the certificates service with a stub that returns ZKGroupError.
	s.certificates = &stubCertificateService{
		credentialErr: &certificates.ZKGroupError{
			Operation: "issue-expiring-profile-key-credential",
			Cause:     errors.New("verification failed"),
		},
	}

	req := httptest.NewRequest(http.MethodGet,
		"/v1/profile/"+testAccountUUID+"/v1/"+reqHex, nil)
	req.SetPathValue("identifier", testAccountUUID)
	req.SetPathValue("version", "v1")
	req.SetPathValue("credentialRequest", reqHex)
	req = req.WithContext(contextWithAccount(req.Context(), nil))

	// Call via router so auth middleware sets the account in context.
	req2 := httptest.NewRequest(http.MethodGet,
		"/v1/profile/"+testAccountUUID+"/v1/"+reqHex, nil)
	req2.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req2)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for ZKGroupError, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --------------------------------------------------------------------------
// handleGetProfileWithCredential — generic certificate error → 500
// --------------------------------------------------------------------------

func TestHandleGetProfileWithCredential_GenericCertErrorReturns500(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	reqHex, commitment := validProfileCredentialRequest(t, testAccountUUID)
	if err := s.profiles.Set(context.Background(), &profiles.Profile{
		UUID:       testAccountUUID,
		Version:    "v1",
		Commitment: commitment,
	}); err != nil {
		t.Fatalf("set profile: %v", err)
	}

	// Replace the certificates service with a stub that returns a generic error.
	s.certificates = &stubCertificateService{credentialErr: errCert}

	req := httptest.NewRequest(http.MethodGet,
		"/v1/profile/"+testAccountUUID+"/v1/"+reqHex, nil)
	req2 := httptest.NewRequest(http.MethodGet,
		"/v1/profile/"+testAccountUUID+"/v1/"+reqHex, nil)
	req2.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req2)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for generic cert error, got %d: %s", rr.Code, rr.Body.String())
	}
	_ = req
}

// --------------------------------------------------------------------------
// Helpers — ensure imported packages are used
// --------------------------------------------------------------------------

// Ensure hex is used (it's imported for the TestHandleGetProfileWithCredential
// tests that call hex.DecodeString indirectly through validProfileCredentialRequest).
var _ = hex.DecodeString
