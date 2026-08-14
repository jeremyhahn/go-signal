//go:build fido2

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/fido2"
)

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

// mockFIDO2WebAuthnProvider is a configurable mock for fido2.WebAuthnProvider
// used in handler tests.
type mockFIDO2WebAuthnProvider struct {
	beginRegistrationFn  func(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	finishRegistrationFn func(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
	beginLoginFn         func(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	finishLoginFn        func(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
}

func (m *mockFIDO2WebAuthnProvider) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	if m.beginRegistrationFn != nil {
		return m.beginRegistrationFn(user, opts...)
	}
	return testCredentialCreation(), testSessionData(), nil
}

func (m *mockFIDO2WebAuthnProvider) FinishRegistration(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	if m.finishRegistrationFn != nil {
		return m.finishRegistrationFn(user, session, response)
	}
	return testWebAuthnCredential(), nil
}

func (m *mockFIDO2WebAuthnProvider) BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if m.beginLoginFn != nil {
		return m.beginLoginFn(user, opts...)
	}
	return testCredentialAssertion(), testSessionData(), nil
}

func (m *mockFIDO2WebAuthnProvider) FinishLogin(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	if m.finishLoginFn != nil {
		return m.finishLoginFn(user, session, response)
	}
	return testWebAuthnCredential(), nil
}

func testCredentialCreation() *protocol.CredentialCreation {
	return &protocol.CredentialCreation{
		Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge: []byte("test-challenge"),
		},
	}
}

func testCredentialAssertion() *protocol.CredentialAssertion {
	return &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte("test-challenge"),
		},
	}
}

func testSessionData() *webauthn.SessionData {
	return &webauthn.SessionData{
		Challenge:      "dGVzdC1jaGFsbGVuZ2U",
		RelyingPartyID: "example.com",
		UserID:         []byte("test-user-id"),
	}
}

func testWebAuthnCredential() *webauthn.Credential {
	return &webauthn.Credential{
		ID:              []byte("test-credential-id"),
		PublicKey:       []byte("test-public-key"),
		AttestationType: "none",
		Transport:       []protocol.AuthenticatorTransport{"usb"},
		Authenticator: webauthn.Authenticator{
			AAGUID:    []byte{0x01, 0x02, 0x03, 0x04},
			SignCount: 1,
		},
	}
}

// testFIDO2Config returns a FIDO2Config suitable for tests.
func testFIDO2Config() *FIDO2Config {
	return &FIDO2Config{
		Enabled:          true,
		RPID:             "example.com",
		RPName:           "Example",
		AllowFIDO2Only:   false,
		RequireMFA:       false,
		Attestation:      "none",
		UserVerification: "preferred",
	}
}

// newTestFIDO2Manager creates a FIDO2AccountsManager with a memory store and
// mock provider.
func newTestFIDO2Manager(provider fido2.WebAuthnProvider) (*fido2.FIDO2AccountsManager, *fido2.MemoryFIDO2AccountsStore) {
	store := fido2.NewMemoryFIDO2AccountsStore()
	mgr := fido2.NewFIDO2AccountsManager(store, provider, fido2.FIDO2AccountsManagerConfig{
		SessionTimeout: 5 * time.Minute,
	})
	return mgr, store
}

// newTestFIDO2Server creates a test REST server with FIDO2 routes registered,
// pre-populated with a test account. Returns the mux (as http.Handler), the
// FIDO2 store, and the server.
func newTestFIDO2Server(t *testing.T, provider fido2.WebAuthnProvider) (http.Handler, *fido2.MemoryFIDO2AccountsStore, *Server) {
	t.Helper()

	s, _ := newTestServerWithAccount(t)
	mgr, store := newTestFIDO2Manager(provider)
	cfg := testFIDO2Config()

	mux := http.NewServeMux()
	s.routes(mux)
	RegisterFIDO2Routes(s, mux, mgr, cfg)

	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	return handler, store, s
}

// seedFIDO2Credential stores a credential directly in the FIDO2 store.
func seedFIDO2Credential(t *testing.T, store *fido2.MemoryFIDO2AccountsStore, credID, accountUUID, name string) {
	t.Helper()
	cred := &fido2.FIDO2Credential{
		CredentialID:    credID,
		AccountUUID:     accountUUID,
		Name:            name,
		PublicKey:       []byte("test-public-key"),
		AttestationType: "none",
		AAGUID:          []byte{0x01, 0x02, 0x03, 0x04},
		SignCount:       0,
		Transport:       []string{"usb"},
		CreatedAt:       time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		LastUsedAt:      time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}
	require.NoError(t, store.CreateCredential(context.Background(), cred))
}

// --------------------------------------------------------------------------
// handleFIDO2Capabilities
// --------------------------------------------------------------------------

func TestHandleFIDO2Capabilities_Success(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodGet, "/v1/fido2/capabilities", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp FIDO2CapabilitiesResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.True(t, resp.Enabled)
	assert.Equal(t, "example.com", resp.RPID)
	assert.Equal(t, "Example", resp.RPName)
	assert.Equal(t, "none", resp.Attestation)
	assert.Equal(t, "preferred", resp.UserVerification)
}

func TestHandleFIDO2Capabilities_NotConfigured(t *testing.T) {
	s := newTestServer(t)
	// Do NOT register FIDO2 routes; the state map has no entry for this server.

	mux := http.NewServeMux()
	// Manually register just the capabilities endpoint so the route matches
	// but the state lookup returns nil.
	mux.HandleFunc("GET /v1/fido2/capabilities", s.handleFIDO2Capabilities)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodGet, "/v1/fido2/capabilities", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2BeginRegistration
// --------------------------------------------------------------------------

func TestHandleFIDO2BeginRegistration_Success(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	body := `{"username":"alice"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/session", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp FIDO2BeginResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Session.SessionID)
	assert.Equal(t, "registration", resp.Session.Type)
	assert.NotZero(t, resp.Session.ExpiresAt)
	assert.NotNil(t, resp.Options)
}

func TestHandleFIDO2BeginRegistration_MissingUsername(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	body := `{"username":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/session", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleFIDO2BeginRegistration_InvalidBody(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/session", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2GetSession
// --------------------------------------------------------------------------

func TestHandleFIDO2GetSession_Success(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	// First, create a session via registration.
	regBody := `{"username":"alice"}`
	regReq := httptest.NewRequest(http.MethodPost, "/v1/fido2/session", strings.NewReader(regBody))
	regRR := httptest.NewRecorder()
	handler.ServeHTTP(regRR, regReq)
	require.Equal(t, http.StatusOK, regRR.Code)

	var beginResp FIDO2BeginResponse
	require.NoError(t, json.Unmarshal(regRR.Body.Bytes(), &beginResp))

	// Now get the session.
	req := httptest.NewRequest(http.MethodGet, "/v1/fido2/session/"+beginResp.Session.SessionID, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp FIDO2SessionResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Equal(t, beginResp.Session.SessionID, resp.SessionID)
	assert.Equal(t, "registration", resp.Type)
}

func TestHandleFIDO2GetSession_NotFound(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodGet, "/v1/fido2/session/nonexistent-id", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2CompleteRegistration
// --------------------------------------------------------------------------

func TestHandleFIDO2CompleteRegistration_SessionNotFound(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/session/nonexistent/complete", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2BeginEnrollment
// --------------------------------------------------------------------------

func TestHandleFIDO2BeginEnrollment_Success(t *testing.T) {
	handler, store, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})
	seedFIDO2Credential(t, store, "existing-cred", testAccountUUID, "Existing Key")

	body := `{"credentialName":"My YubiKey"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/enroll", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp FIDO2BeginResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Session.SessionID)
	assert.Equal(t, "enrollment", resp.Session.Type)
}

func TestHandleFIDO2BeginEnrollment_Unauthenticated(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	body := `{"credentialName":"My YubiKey"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/enroll", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2BeginLogin
// --------------------------------------------------------------------------

func TestHandleFIDO2BeginLogin_Success(t *testing.T) {
	handler, store, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})
	seedFIDO2Credential(t, store, "login-cred", testAccountUUID, "Login Key")

	body := `{"accountUuid":"` + testAccountUUID + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/begin", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp FIDO2BeginResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Session.SessionID)
	assert.Equal(t, "login", resp.Session.Type)
}

func TestHandleFIDO2BeginLogin_NoCredentials(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	body := `{"accountUuid":"` + testAccountUUID + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/begin", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2BeginLogin_MissingAccountUUID(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	body := `{"accountUuid":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/begin", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleFIDO2BeginLogin_Unauthenticated(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	body := `{"accountUuid":"` + testAccountUUID + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/begin", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2CompleteLogin
// --------------------------------------------------------------------------

func TestHandleFIDO2CompleteLogin_MissingSessionID(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	body := `{"sessionId":""}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/complete", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleFIDO2CompleteLogin_SessionNotFound(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	body := `{"sessionId":"nonexistent"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/complete", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2ListCredentials
// --------------------------------------------------------------------------

func TestHandleFIDO2ListCredentials_Success(t *testing.T) {
	handler, store, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})
	seedFIDO2Credential(t, store, "cred-1", testAccountUUID, "Key 1")
	seedFIDO2Credential(t, store, "cred-2", testAccountUUID, "Key 2")

	req := httptest.NewRequest(http.MethodGet, "/v1/fido2/credentials", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp FIDO2CredentialListResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Len(t, resp.Credentials, 2)

	// Verify the response fields are populated.
	for _, c := range resp.Credentials {
		assert.NotEmpty(t, c.CredentialID)
		assert.NotEmpty(t, c.Name)
		assert.Equal(t, "none", c.AttestationType)
		assert.NotNil(t, c.Transport)
		assert.NotZero(t, c.CreatedAt)
		assert.NotZero(t, c.LastUsedAt)
	}
}

func TestHandleFIDO2ListCredentials_Empty(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodGet, "/v1/fido2/credentials", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var resp FIDO2CredentialListResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.Empty(t, resp.Credentials)
	assert.NotNil(t, resp.Credentials)
}

func TestHandleFIDO2ListCredentials_Unauthenticated(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodGet, "/v1/fido2/credentials", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2DeleteCredential
// --------------------------------------------------------------------------

func TestHandleFIDO2DeleteCredential_Success(t *testing.T) {
	handler, store, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})
	seedFIDO2Credential(t, store, "to-delete", testAccountUUID, "Delete Me")

	req := httptest.NewRequest(http.MethodDelete, "/v1/fido2/credentials/to-delete", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify the credential is gone.
	_, err := store.GetCredential(context.Background(), "to-delete")
	assert.Error(t, err)
}

func TestHandleFIDO2DeleteCredential_NotFound(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodDelete, "/v1/fido2/credentials/nonexistent", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2DeleteCredential_Unauthenticated(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodDelete, "/v1/fido2/credentials/some-id", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2RenameCredential
// --------------------------------------------------------------------------

func TestHandleFIDO2RenameCredential_Success(t *testing.T) {
	handler, store, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})
	seedFIDO2Credential(t, store, "to-rename", testAccountUUID, "Old Name")

	body := `{"name":"New Name"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/fido2/credentials/to-rename/name", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)

	// Verify the name was updated.
	cred, err := store.GetCredential(context.Background(), "to-rename")
	require.NoError(t, err)
	assert.Equal(t, "New Name", cred.Name)
}

func TestHandleFIDO2RenameCredential_MissingName(t *testing.T) {
	handler, store, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})
	seedFIDO2Credential(t, store, "to-rename-2", testAccountUUID, "Old Name")

	body := `{"name":""}`
	req := httptest.NewRequest(http.MethodPut, "/v1/fido2/credentials/to-rename-2/name", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleFIDO2RenameCredential_NotFound(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	body := `{"name":"New Name"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/fido2/credentials/nonexistent/name", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2RenameCredential_Unauthenticated(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	body := `{"name":"New Name"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/fido2/credentials/some-id/name", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

// --------------------------------------------------------------------------
// writeFIDO2Error mapping tests
// --------------------------------------------------------------------------

func TestWriteFIDO2Error_CredentialNotFound(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFIDO2Error(rr, &fido2.CredentialNotFoundError{CredentialID: "abc"})
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestWriteFIDO2Error_SessionNotFound(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFIDO2Error(rr, &fido2.SessionNotFoundError{SessionID: "abc"})
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestWriteFIDO2Error_NoCredentials(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFIDO2Error(rr, &fido2.NoCredentialsError{AccountUUID: "abc"})
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestWriteFIDO2Error_SessionExpired(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFIDO2Error(rr, &fido2.SessionExpiredError{SessionID: "abc"})
	assert.Equal(t, http.StatusGone, rr.Code)
}

func TestWriteFIDO2Error_CeremonyError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFIDO2Error(rr, &fido2.CeremonyError{Phase: "begin_registration"})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestWriteFIDO2Error_InvalidSessionType(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFIDO2Error(rr, &fido2.InvalidSessionTypeError{Expected: "registration", Got: "login"})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestWriteFIDO2Error_UnknownError(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFIDO2Error(rr, &DecodeError{Message: "unknown"})
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// --------------------------------------------------------------------------
// credentialToResponse
// --------------------------------------------------------------------------

func TestCredentialToResponse_PopulatesFields(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	cred := &fido2.FIDO2Credential{
		CredentialID:    "test-id",
		Name:            "My Key",
		AttestationType: "none",
		Transport:       []string{"usb", "nfc"},
		CreatedAt:       now,
		LastUsedAt:      now,
	}

	resp := credentialToResponse(cred)
	assert.Equal(t, "test-id", resp.CredentialID)
	assert.Equal(t, "My Key", resp.Name)
	assert.Equal(t, "none", resp.AttestationType)
	assert.Equal(t, []string{"usb", "nfc"}, resp.Transport)
	assert.Equal(t, now.Unix(), resp.CreatedAt)
	assert.Equal(t, now.Unix(), resp.LastUsedAt)
}

func TestCredentialToResponse_NilTransportBecomesEmptySlice(t *testing.T) {
	cred := &fido2.FIDO2Credential{
		CredentialID: "test-id",
		Transport:    nil,
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
	}

	resp := credentialToResponse(cred)
	assert.NotNil(t, resp.Transport)
	assert.Empty(t, resp.Transport)
}

// --------------------------------------------------------------------------
// FIDO2 state management
// --------------------------------------------------------------------------

func TestFIDO2State_SetGetRemove(t *testing.T) {
	s := newTestServer(t)
	state := &fido2State{config: testFIDO2Config()}

	// Initially nil.
	assert.Nil(t, getFIDO2State(s))

	// Set and get.
	setFIDO2State(s, state)
	got := getFIDO2State(s)
	assert.Equal(t, state, got)

	// Remove.
	removeFIDO2State(s)
	assert.Nil(t, getFIDO2State(s))
}

// --------------------------------------------------------------------------
// Interface compliance
// --------------------------------------------------------------------------

func TestMockFIDO2WebAuthnProvider_InterfaceCompliance(t *testing.T) {
	var _ fido2.WebAuthnProvider = (*mockFIDO2WebAuthnProvider)(nil)
}

// --------------------------------------------------------------------------
// handleFIDO2CompleteEnrollment (0% -> covered)
// --------------------------------------------------------------------------

func TestHandleFIDO2CompleteEnrollment_NotConfigured(t *testing.T) {
	s := newTestServer(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/fido2/enroll/{id}/complete", s.handleFIDO2CompleteEnrollment)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/enroll/some-id/complete", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2CompleteEnrollment_MissingSessionID(t *testing.T) {
	s := newTestServer(t)
	mgr, _ := newTestFIDO2Manager(&mockFIDO2WebAuthnProvider{})
	cfg := testFIDO2Config()
	mux := http.NewServeMux()
	s.routes(mux)
	RegisterFIDO2Routes(s, mux, mgr, cfg)
	mux.HandleFunc("POST /v1/fido2/enroll-no-id/complete", s.handleFIDO2CompleteEnrollment)
	h := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/enroll-no-id/complete", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleFIDO2CompleteEnrollment_SessionNotFound(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/enroll/nonexistent-session/complete", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2CompleteEnrollment_Success(t *testing.T) {
	handler, store, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	seedFIDO2Credential(t, store, "existing-cred-for-enroll", testAccountUUID, "Primary Key")

	enrollBody := `{"credentialName":"Second Key"}`
	enrollReq := httptest.NewRequest(http.MethodPost, "/v1/fido2/enroll", strings.NewReader(enrollBody))
	enrollReq.SetBasicAuth(testAccountUUID, testAuthToken)
	enrollRR := httptest.NewRecorder()
	handler.ServeHTTP(enrollRR, enrollReq)
	require.Equal(t, http.StatusOK, enrollRR.Code)

	var beginResp FIDO2BeginResponse
	require.NoError(t, json.Unmarshal(enrollRR.Body.Bytes(), &beginResp))
	sessionID := beginResp.Session.SessionID
	require.NotEmpty(t, sessionID)

	completeReq := httptest.NewRequest(http.MethodPost, "/v1/fido2/enroll/"+sessionID+"/complete", nil)
	completeReq.SetBasicAuth(testAccountUUID, testAuthToken)
	completeRR := httptest.NewRecorder()
	handler.ServeHTTP(completeRR, completeReq)

	require.Equal(t, http.StatusOK, completeRR.Code)

	var credResp FIDO2CredentialResponse
	require.NoError(t, json.Unmarshal(completeRR.Body.Bytes(), &credResp))
	assert.NotEmpty(t, credResp.CredentialID)
}

// --------------------------------------------------------------------------
// handleFIDO2CompleteRegistration - additional branches
// --------------------------------------------------------------------------

func TestHandleFIDO2CompleteRegistration_NotConfigured(t *testing.T) {
	s := newTestServer(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/fido2/session/{id}/complete", s.handleFIDO2CompleteRegistration)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/session/some-id/complete", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2CompleteRegistration_MissingSessionID(t *testing.T) {
	s := newTestServer(t)
	mgr, _ := newTestFIDO2Manager(&mockFIDO2WebAuthnProvider{})
	cfg := testFIDO2Config()
	mux := http.NewServeMux()
	s.routes(mux)
	RegisterFIDO2Routes(s, mux, mgr, cfg)
	mux.HandleFunc("POST /v1/fido2/session-no-id/complete", s.handleFIDO2CompleteRegistration)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/session-no-id/complete", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleFIDO2CompleteRegistration_Success(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	regBody := `{"username":"alice"}`
	regReq := httptest.NewRequest(http.MethodPost, "/v1/fido2/session", strings.NewReader(regBody))
	regRR := httptest.NewRecorder()
	handler.ServeHTTP(regRR, regReq)
	require.Equal(t, http.StatusOK, regRR.Code)

	var beginResp FIDO2BeginResponse
	require.NoError(t, json.Unmarshal(regRR.Body.Bytes(), &beginResp))
	sessionID := beginResp.Session.SessionID
	require.NotEmpty(t, sessionID)

	completeReq := httptest.NewRequest(http.MethodPost, "/v1/fido2/session/"+sessionID+"/complete", nil)
	completeRR := httptest.NewRecorder()
	handler.ServeHTTP(completeRR, completeReq)

	require.Equal(t, http.StatusOK, completeRR.Code)

	var credResp FIDO2CredentialResponse
	require.NoError(t, json.Unmarshal(completeRR.Body.Bytes(), &credResp))
	assert.NotEmpty(t, credResp.CredentialID)
	assert.Equal(t, "none", credResp.AttestationType)
}

// --------------------------------------------------------------------------
// handleFIDO2GetSession - additional branches
// --------------------------------------------------------------------------

func TestHandleFIDO2GetSession_NotConfigured(t *testing.T) {
	s := newTestServer(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/fido2/session/{id}", s.handleFIDO2GetSession)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodGet, "/v1/fido2/session/abc", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2GetSession_MissingSessionID(t *testing.T) {
	s := newTestServer(t)
	mgr, _ := newTestFIDO2Manager(&mockFIDO2WebAuthnProvider{})
	cfg := testFIDO2Config()
	mux := http.NewServeMux()
	s.routes(mux)
	RegisterFIDO2Routes(s, mux, mgr, cfg)
	mux.HandleFunc("GET /v1/fido2/session-no-id", s.handleFIDO2GetSession)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodGet, "/v1/fido2/session-no-id", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2BeginEnrollment - additional branches
// --------------------------------------------------------------------------

func TestHandleFIDO2BeginEnrollment_NotConfigured(t *testing.T) {
	s := newTestServer(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/fido2/enroll", s.handleFIDO2BeginEnrollment)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/enroll", strings.NewReader(`{"credentialName":"test"}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2BeginEnrollment_InvalidBody(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/enroll", strings.NewReader("not json"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleFIDO2BeginEnrollment_ProviderError(t *testing.T) {
	errProvider := &mockFIDO2WebAuthnProvider{
		beginRegistrationFn: func(_ webauthn.User, _ ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
			return nil, nil, errors.New("provider failure")
		},
	}
	handler, _, _ := newTestFIDO2Server(t, errProvider)

	body := `{"credentialName":"My YubiKey"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/enroll", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// The provider error is wrapped in a CeremonyError -> 400 Bad Request.
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2BeginRegistration - not configured
// --------------------------------------------------------------------------

func TestHandleFIDO2BeginRegistration_NotConfigured(t *testing.T) {
	s := newTestServer(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/fido2/session", s.handleFIDO2BeginRegistration)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	body := `{"username":"alice"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/session", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2ListCredentials - additional branches
// --------------------------------------------------------------------------

func TestHandleFIDO2ListCredentials_NotConfigured(t *testing.T) {
	s := newTestServer(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/fido2/credentials", s.handleFIDO2ListCredentials)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodGet, "/v1/fido2/credentials", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2DeleteCredential - additional branches
// --------------------------------------------------------------------------

func TestHandleFIDO2DeleteCredential_NotConfigured(t *testing.T) {
	s := newTestServer(t)

	mux := http.NewServeMux()
	mux.HandleFunc("DELETE /v1/fido2/credentials/{id}", s.handleFIDO2DeleteCredential)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodDelete, "/v1/fido2/credentials/abc", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2DeleteCredential_MissingCredentialID(t *testing.T) {
	_, _, s := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	mux := http.NewServeMux()
	s.routes(mux)
	mgr, _ := newTestFIDO2Manager(&mockFIDO2WebAuthnProvider{})
	RegisterFIDO2Routes(s, mux, mgr, testFIDO2Config())
	// Register a route without path parameter but still wrapped with authMiddleware.
	mux.HandleFunc("DELETE /v1/fido2/credentials-no-id", authMiddleware(s.accounts, s.handleFIDO2DeleteCredential))
	h := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodDelete, "/v1/fido2/credentials-no-id", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2RenameCredential - additional branches
// --------------------------------------------------------------------------

func TestHandleFIDO2RenameCredential_NotConfigured(t *testing.T) {
	s := newTestServer(t)

	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/fido2/credentials/{id}/name", s.handleFIDO2RenameCredential)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	req := httptest.NewRequest(http.MethodPut, "/v1/fido2/credentials/abc/name", strings.NewReader(`{"name":"Test"}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2RenameCredential_MissingCredentialID(t *testing.T) {
	_, _, s := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	mux := http.NewServeMux()
	s.routes(mux)
	mgr, _ := newTestFIDO2Manager(&mockFIDO2WebAuthnProvider{})
	RegisterFIDO2Routes(s, mux, mgr, testFIDO2Config())
	mux.HandleFunc("PUT /v1/fido2/credentials-no-id/name", authMiddleware(s.accounts, s.handleFIDO2RenameCredential))
	h := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	body := `{"name":"New Name"}`
	req := httptest.NewRequest(http.MethodPut, "/v1/fido2/credentials-no-id/name", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleFIDO2RenameCredential_InvalidBody(t *testing.T) {
	handler, store, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})
	seedFIDO2Credential(t, store, "rename-invalid-body", testAccountUUID, "Key")

	req := httptest.NewRequest(http.MethodPut, "/v1/fido2/credentials/rename-invalid-body/name", strings.NewReader("not json"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// handleFIDO2CompleteLogin - additional branches
// --------------------------------------------------------------------------

func TestHandleFIDO2CompleteLogin_NotConfigured(t *testing.T) {
	s := newTestServer(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/fido2/auth/complete", s.handleFIDO2CompleteLogin)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	body := `{"sessionId":"abc"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/complete", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2CompleteLogin_InvalidBody(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/complete", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleFIDO2CompleteLogin_Success(t *testing.T) {
	handler, store, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	seedFIDO2Credential(t, store, "login-cred-complete", testAccountUUID, "Login Key")

	loginBody := `{"accountUuid":"` + testAccountUUID + `"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/begin", strings.NewReader(loginBody))
	loginReq.SetBasicAuth(testAccountUUID, testAuthToken)
	loginRR := httptest.NewRecorder()
	handler.ServeHTTP(loginRR, loginReq)
	require.Equal(t, http.StatusOK, loginRR.Code)

	var beginResp FIDO2BeginResponse
	require.NoError(t, json.Unmarshal(loginRR.Body.Bytes(), &beginResp))
	sessionID := beginResp.Session.SessionID

	completeBody := `{"sessionId":"` + sessionID + `"}`
	completeReq := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/complete", strings.NewReader(completeBody))
	completeRR := httptest.NewRecorder()
	handler.ServeHTTP(completeRR, completeReq)

	require.Equal(t, http.StatusOK, completeRR.Code)

	var loginResp FIDO2LoginResponse
	require.NoError(t, json.Unmarshal(completeRR.Body.Bytes(), &loginResp))
	assert.Equal(t, testAccountUUID, loginResp.AccountUUID)
}

// --------------------------------------------------------------------------
// handleFIDO2BeginLogin - additional branches
// --------------------------------------------------------------------------

func TestHandleFIDO2BeginLogin_NotConfigured(t *testing.T) {
	s := newTestServer(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/fido2/auth/begin", s.handleFIDO2BeginLogin)
	handler := jsonMiddleware(loggingMiddleware(testLogger(), mux))

	body := `{"accountUuid":"abc"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/begin", strings.NewReader(body))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
}

func TestHandleFIDO2BeginLogin_InvalidBody(t *testing.T) {
	handler, _, _ := newTestFIDO2Server(t, &mockFIDO2WebAuthnProvider{})

	req := httptest.NewRequest(http.MethodPost, "/v1/fido2/auth/begin", strings.NewReader("not json"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --------------------------------------------------------------------------
// writeFIDO2Error - CredentialExistsError branch
// --------------------------------------------------------------------------

func TestWriteFIDO2Error_CredentialExists(t *testing.T) {
	rr := httptest.NewRecorder()
	writeFIDO2Error(rr, &fido2.CredentialExistsError{CredentialID: "abc"})
	assert.Equal(t, http.StatusConflict, rr.Code)
}
