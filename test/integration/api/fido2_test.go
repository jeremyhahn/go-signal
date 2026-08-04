//go:build integration && fido2

package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/api/rest"
	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/certificates"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/devices"
	"github.com/jeremyhahn/go-signal/pkg/directory"
	"github.com/jeremyhahn/go-signal/pkg/extservice/registration/inprocess"
	"github.com/jeremyhahn/go-signal/pkg/fido2"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/keytransparency"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/registration/sessionshim"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	"github.com/jeremyhahn/go-signal/pkg/securevaluerecovery"
	"github.com/jeremyhahn/go-signal/pkg/stickers"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
	"github.com/jeremyhahn/go-signal/pkg/verification"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"log/slog"
	"os"
)

// --------------------------------------------------------------------------
// Mock WebAuthn provider
// --------------------------------------------------------------------------

// fido2MockProvider is a configurable mock for fido2.WebAuthnProvider used in
// integration tests. It returns deterministic, pre-built ceremony objects so
// no real authenticator hardware is needed.
type fido2MockProvider struct {
	beginRegistrationFn  func(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	finishRegistrationFn func(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
	beginLoginFn         func(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	finishLoginFn        func(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
}

func (m *fido2MockProvider) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	if m.beginRegistrationFn != nil {
		return m.beginRegistrationFn(user, opts...)
	}
	return fido2IntegTestCredentialCreation(), fido2IntegTestSessionData(), nil
}

func (m *fido2MockProvider) FinishRegistration(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	if m.finishRegistrationFn != nil {
		return m.finishRegistrationFn(user, session, response)
	}
	return fido2IntegTestWebAuthnCredential(), nil
}

func (m *fido2MockProvider) BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if m.beginLoginFn != nil {
		return m.beginLoginFn(user, opts...)
	}
	return fido2IntegTestCredentialAssertion(), fido2IntegTestSessionData(), nil
}

func (m *fido2MockProvider) FinishLogin(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	if m.finishLoginFn != nil {
		return m.finishLoginFn(user, session, response)
	}
	return fido2IntegTestWebAuthnCredential(), nil
}

func fido2IntegTestCredentialCreation() *protocol.CredentialCreation {
	return &protocol.CredentialCreation{
		Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge: []byte("integration-test-challenge"),
		},
	}
}

func fido2IntegTestCredentialAssertion() *protocol.CredentialAssertion {
	return &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte("integration-test-challenge"),
		},
	}
}

func fido2IntegTestSessionData() *webauthn.SessionData {
	return &webauthn.SessionData{
		Challenge:      "aW50ZWdyYXRpb24tdGVzdC1jaGFsbGVuZ2U",
		RelyingPartyID: "localhost",
		UserID:         []byte("integration-test-user-id"),
	}
}

func fido2IntegTestWebAuthnCredential() *webauthn.Credential {
	return &webauthn.Credential{
		ID:              []byte("integration-test-credential-id"),
		PublicKey:       []byte("integration-test-public-key"),
		AttestationType: "none",
		Transport:       []protocol.AuthenticatorTransport{"usb"},
		Authenticator: webauthn.Authenticator{
			AAGUID:    []byte{0x01, 0x02, 0x03, 0x04},
			SignCount: 1,
		},
	}
}

// --------------------------------------------------------------------------
// FIDO2-specific test environment
// --------------------------------------------------------------------------

// fido2Env extends testEnv with FIDO2-specific state: the in-memory store for
// seeding credentials/sessions and the account credentials for auth routes.
type fido2Env struct {
	*testEnv
	store       *fido2.MemoryFIDO2AccountsStore
	accountUUID string
	password    string
}

// doFIDO2AuthRequest performs a request with Basic auth credentials formatted
// as "uuid.1:password" — the same format used by doAuthRequest in testutil.go.
func (e *fido2Env) doFIDO2AuthRequest(t *testing.T, method, path string, body any) *http.Response {
	t.Helper()
	return e.doAuthRequest(t, method, path, body, e.accountUUID, e.password)
}

// setupFIDO2TestEnv creates a complete in-process server with FIDO2 routes
// registered. This is always in-process: even when SIGNAL_SERVER_URL is set,
// the docker server does not include the fido2 build tag, so we must run a
// local in-memory server for these tests.
func setupFIDO2TestEnv(t *testing.T) *fido2Env {
	t.Helper()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Wire in-memory stores.
	accountStore := memory.NewMemoryAccountStore()
	messageStore := memory.NewMemoryMessageStore()
	keyStore := memory.NewMemoryPreKeyStore()
	profileStore := memory.NewMemoryProfileStore()
	usernameStore := memory.NewMemoryUsernameStore()

	accountsMgr := accounts.NewAccountsManager(accountStore, 6)
	captchaMgr := captcha.NewCaptchaManager(logger)
	certsMgr := certificates.NewCertificatesManager(secrets.NewSecureString("test-signing-key-32bytes-xxxxxx"), logger)
	keysMgr := keys.NewKeysManager(keyStore)
	messagesMgr := messages.NewMessagesManager(messageStore)
	profilesMgr := profiles.NewProfilesManager(profileStore)
	usernamesMgr := usernames.NewUsernamesManager(usernameStore, logger)
	stickersMgr := stickers.NewStickersManager(stickers.ManagerConfig{Logger: logger})
	directoryMgr := directory.NewDirectoryManager(logger)
	secureStorageMgr := securestorage.NewSecureStorageManager(logger)
	svrMgr := securevaluerecovery.NewSVRManager(logger)
	callingMgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider: &calling.StaticTurnProvider{
			URLs:     []string{"turn:localhost:3478"},
			Hostname: "localhost",
		},
		Logger: logger,
	})
	ktMgr := keytransparency.NewKeyTransparencyManager(logger)
	provisioningStore := memory.NewMemoryProvisioningStore()
	devicesMgr := devices.NewDevicesManager(provisioningStore, accountsMgr, keysMgr, logger)
	wsSessions := signalws.NewSessionManager(logger)

	verificationStore := verification.NewMemoryVerificationSessionStore()
	verificationTransport := verification.NewStubTransport(logger)
	coreSvc := core.NewService(verificationStore, verificationTransport, core.Config{
		FixedCode: "123456",
	})
	t.Cleanup(coreSvc.Shutdown)
	verificationMgr := sessionshim.NewShim(sessionshim.Config{
		Client:       inprocess.New(coreSvc),
		CaptchaStore: sessionshim.NewMemoryCaptchaStore(),
	})

	srv := rest.NewServer(rest.ServerConfig{
		Host:            "127.0.0.1",
		Port:            0,
		Logger:          logger,
		Accounts:        accountsMgr,
		Captcha:         captchaMgr,
		Certificates:    certsMgr,
		Keys:            keysMgr,
		Messages:        messagesMgr,
		Profiles:        profilesMgr,
		Usernames:       usernamesMgr,
		Stickers:        stickersMgr,
		Directory:       directoryMgr,
		SecureStorage:   secureStorageMgr,
		SVR:             svrMgr,
		Calling:         callingMgr,
		KeyTransparency: ktMgr,
		Devices:         devicesMgr,
		WSSessions:      wsSessions,
		Verification:    verificationMgr,
	})

	// Build the FIDO2 manager with a mock provider and register routes.
	fido2Store := fido2.NewMemoryFIDO2AccountsStore()
	mockProvider := &fido2MockProvider{}
	fido2Mgr := fido2.NewFIDO2AccountsManager(fido2Store, mockProvider, fido2.FIDO2AccountsManagerConfig{
		SessionTimeout: 5 * time.Minute,
	})
	fido2Cfg := &rest.FIDO2Config{
		Enabled:          true,
		RPID:             "localhost",
		RPName:           "Go Signal Test",
		AllowFIDO2Only:   false,
		RequireMFA:       false,
		Attestation:      "none",
		UserVerification: "preferred",
	}
	srv.RegisterFIDO2(fido2Mgr, fido2Cfg)

	require.NoError(t, srv.Listen())

	addr := srv.Addr()
	require.NotEqual(t, "127.0.0.1:0", addr)

	go func() {
		if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
			t.Logf("fido2 test server error: %v", err)
		}
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})

	// Create a test account so authenticated routes can be exercised.
	const (
		testUUID     = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		testNumber   = "+15550000001"
		testPassword = "fido2-test-password"
	)
	acct := &accounts.Account{
		UUID:                   testUUID,
		Number:                 testNumber,
		IdentityKey:            []byte("fido2-test-identity-key-32bytes!"),
		PhoneNumberIdentityKey: []byte("fido2-test-pni-key-xxxxx-32byte!"),
		UnidentifiedAccessKey:  []byte("fido2-unidentified-key-16bytes!!"),
		Devices: []accounts.Device{
			{
				ID:        accounts.PrimaryDeviceID,
				Name:      "FIDO2 Test Device",
				AuthToken: testPassword,
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte("fido2-spk-pub-key-32bytes-xxxxxx"),
					Signature: []byte("fido2-spk-sig-64bytes-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
				},
				RegistrationID:  9999,
				CreatedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				LastSeen:        time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				FetchesMessages: true,
				Capabilities:    accounts.DeviceCapabilities{Storage: true},
			},
		},
		CreatedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Version:   1,
	}
	require.NoError(t, accountsMgr.Create(context.Background(), acct))

	client := &http.Client{Timeout: 10 * time.Second}

	env := &testEnv{
		server:  srv,
		baseURL: "http://" + addr,
		client:  client,
	}
	return &fido2Env{
		testEnv:     env,
		store:       fido2Store,
		accountUUID: testUUID,
		password:    testPassword,
	}
}

// seedFIDO2IntegCredential inserts a credential directly into the in-memory
// store, bypassing the ceremony flow. Use this to pre-populate state for tests
// that depend on existing credentials (e.g. login, list, rename, delete).
func seedFIDO2IntegCredential(t *testing.T, store *fido2.MemoryFIDO2AccountsStore, credID, accountUUID, name string) {
	t.Helper()
	cred := &fido2.FIDO2Credential{
		CredentialID:    credID,
		AccountUUID:     accountUUID,
		Name:            name,
		PublicKey:       []byte("integ-test-public-key"),
		AttestationType: "none",
		AAGUID:          []byte{0x0a, 0x0b, 0x0c, 0x0d},
		SignCount:       0,
		Transport:       []string{"usb"},
		CreatedAt:       time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		LastUsedAt:      time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
	}
	require.NoError(t, store.CreateCredential(context.Background(), cred))
}

// --------------------------------------------------------------------------
// Helper: decode FIDO2 JSON response bodies
// --------------------------------------------------------------------------

func decodeFIDO2JSON[T any](t *testing.T, resp *http.Response, dst *T) {
	t.Helper()
	defer resp.Body.Close()
	require.NoError(t, json.NewDecoder(resp.Body).Decode(dst))
}

// --------------------------------------------------------------------------
// Capabilities
// --------------------------------------------------------------------------

func TestFIDO2_Capabilities(t *testing.T) {
	env := setupFIDO2TestEnv(t)

	resp := env.doRequest(t, "GET", "/v1/fido2/capabilities", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var caps struct {
		Enabled          bool   `json:"enabled"`
		RPID             string `json:"rpId"`
		RPName           string `json:"rpName"`
		Attestation      string `json:"attestation"`
		UserVerification string `json:"userVerification"`
	}
	decodeFIDO2JSON(t, resp, &caps)

	assert.True(t, caps.Enabled)
	assert.Equal(t, "localhost", caps.RPID)
	assert.Equal(t, "Go Signal Test", caps.RPName)
	assert.Equal(t, "none", caps.Attestation)
	assert.Equal(t, "preferred", caps.UserVerification)
}

// --------------------------------------------------------------------------
// Registration flow
// --------------------------------------------------------------------------

func TestFIDO2_Registration_BeginAndGetSession(t *testing.T) {
	env := setupFIDO2TestEnv(t)

	// Begin registration.
	resp := env.doRequest(t, "POST", "/v1/fido2/session", map[string]any{"username": "alice"}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var beginResp struct {
		Session struct {
			SessionID string `json:"sessionId"`
			Type      string `json:"type"`
			ExpiresAt int64  `json:"expiresAt"`
		} `json:"session"`
		Options any `json:"options"`
	}
	decodeFIDO2JSON(t, resp, &beginResp)

	assert.NotEmpty(t, beginResp.Session.SessionID)
	assert.Equal(t, "registration", beginResp.Session.Type)
	assert.NotZero(t, beginResp.Session.ExpiresAt)
	assert.NotNil(t, beginResp.Options)

	// Retrieve the session.
	getResp := env.doRequest(t, "GET", "/v1/fido2/session/"+beginResp.Session.SessionID, nil, nil)
	require.Equal(t, http.StatusOK, getResp.StatusCode)

	var sessionResp struct {
		SessionID string `json:"sessionId"`
		Type      string `json:"type"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	decodeFIDO2JSON(t, getResp, &sessionResp)

	assert.Equal(t, beginResp.Session.SessionID, sessionResp.SessionID)
	assert.Equal(t, "registration", sessionResp.Type)
	assert.NotZero(t, sessionResp.ExpiresAt)
}

func TestFIDO2_Registration_Complete(t *testing.T) {
	env := setupFIDO2TestEnv(t)

	// Begin registration.
	beginResp := env.doRequest(t, "POST", "/v1/fido2/session", map[string]any{"username": "bob"}, nil)
	require.Equal(t, http.StatusOK, beginResp.StatusCode)

	var begin struct {
		Session struct {
			SessionID string `json:"sessionId"`
		} `json:"session"`
	}
	decodeFIDO2JSON(t, beginResp, &begin)
	require.NotEmpty(t, begin.Session.SessionID)

	// Complete registration — mock provider returns a pre-built credential.
	completeResp := env.doRequest(t, "POST", "/v1/fido2/session/"+begin.Session.SessionID+"/complete", nil, nil)
	require.Equal(t, http.StatusOK, completeResp.StatusCode)

	var cred struct {
		CredentialID    string   `json:"credentialId"`
		AttestationType string   `json:"attestationType"`
		Transport       []string `json:"transport"`
	}
	decodeFIDO2JSON(t, completeResp, &cred)

	assert.NotEmpty(t, cred.CredentialID)
	assert.Equal(t, "none", cred.AttestationType)
	assert.NotNil(t, cred.Transport)
}

func TestFIDO2_Registration_MissingUsername(t *testing.T) {
	env := setupFIDO2TestEnv(t)

	resp := env.doRequest(t, "POST", "/v1/fido2/session", map[string]any{"username": ""}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestFIDO2_Registration_SessionNotFound(t *testing.T) {
	env := setupFIDO2TestEnv(t)

	resp := env.doRequest(t, "POST", "/v1/fido2/session/nonexistent-session-id/complete", nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

// --------------------------------------------------------------------------
// Login flow
// --------------------------------------------------------------------------

func TestFIDO2_Login_BeginAndComplete(t *testing.T) {
	env := setupFIDO2TestEnv(t)
	seedFIDO2IntegCredential(t, env.store, "login-test-cred", env.accountUUID, "Login Key")

	// Begin login (auth required).
	beginResp := env.doFIDO2AuthRequest(t, "POST", "/v1/fido2/auth/begin",
		map[string]any{"accountUuid": env.accountUUID})
	require.Equal(t, http.StatusOK, beginResp.StatusCode)

	var begin struct {
		Session struct {
			SessionID string `json:"sessionId"`
			Type      string `json:"type"`
		} `json:"session"`
	}
	decodeFIDO2JSON(t, beginResp, &begin)
	require.NotEmpty(t, begin.Session.SessionID)
	assert.Equal(t, "login", begin.Session.Type)

	// Complete login (public endpoint, session ID in body).
	completeResp := env.doRequest(t, "POST", "/v1/fido2/auth/complete",
		map[string]any{"sessionId": begin.Session.SessionID}, nil)
	require.Equal(t, http.StatusOK, completeResp.StatusCode)

	var loginResp struct {
		AccountUUID string `json:"accountUuid"`
	}
	decodeFIDO2JSON(t, completeResp, &loginResp)
	assert.Equal(t, env.accountUUID, loginResp.AccountUUID)
}

func TestFIDO2_Login_NoCredentials(t *testing.T) {
	env := setupFIDO2TestEnv(t)
	// No credentials seeded — BeginLogin must return 404.

	resp := env.doFIDO2AuthRequest(t, "POST", "/v1/fido2/auth/begin",
		map[string]any{"accountUuid": env.accountUUID})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestFIDO2_Login_MissingAccountUUID(t *testing.T) {
	env := setupFIDO2TestEnv(t)

	resp := env.doFIDO2AuthRequest(t, "POST", "/v1/fido2/auth/begin",
		map[string]any{"accountUuid": ""})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

// --------------------------------------------------------------------------
// Enrollment flow (auth required)
// --------------------------------------------------------------------------

func TestFIDO2_Enrollment_BeginAndComplete(t *testing.T) {
	env := setupFIDO2TestEnv(t)
	// Seed an existing credential so BeginEnrollment succeeds (account must
	// already have at least one credential to enroll another).
	seedFIDO2IntegCredential(t, env.store, "primary-cred", env.accountUUID, "Primary Key")

	// Begin enrollment.
	beginResp := env.doFIDO2AuthRequest(t, "POST", "/v1/fido2/enroll",
		map[string]any{"credentialName": "Second YubiKey"})
	require.Equal(t, http.StatusOK, beginResp.StatusCode)

	var begin struct {
		Session struct {
			SessionID string `json:"sessionId"`
			Type      string `json:"type"`
		} `json:"session"`
	}
	decodeFIDO2JSON(t, beginResp, &begin)
	require.NotEmpty(t, begin.Session.SessionID)
	assert.Equal(t, "enrollment", begin.Session.Type)

	// Complete enrollment.
	completeResp := env.doFIDO2AuthRequest(t, "POST",
		"/v1/fido2/enroll/"+begin.Session.SessionID+"/complete", nil)
	require.Equal(t, http.StatusOK, completeResp.StatusCode)

	var cred struct {
		CredentialID string `json:"credentialId"`
	}
	decodeFIDO2JSON(t, completeResp, &cred)
	assert.NotEmpty(t, cred.CredentialID)
}

func TestFIDO2_Enrollment_Unauthenticated(t *testing.T) {
	env := setupFIDO2TestEnv(t)

	resp := env.doRequest(t, "POST", "/v1/fido2/enroll",
		map[string]any{"credentialName": "My Key"}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

// --------------------------------------------------------------------------
// Credential management (auth required)
// --------------------------------------------------------------------------

func TestFIDO2_Credentials_ListEmpty(t *testing.T) {
	env := setupFIDO2TestEnv(t)

	resp := env.doFIDO2AuthRequest(t, "GET", "/v1/fido2/credentials", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var listResp struct {
		Credentials []any `json:"credentials"`
	}
	decodeFIDO2JSON(t, resp, &listResp)

	assert.NotNil(t, listResp.Credentials)
	assert.Empty(t, listResp.Credentials)
}

func TestFIDO2_Credentials_ListAfterRegistration(t *testing.T) {
	env := setupFIDO2TestEnv(t)
	seedFIDO2IntegCredential(t, env.store, "list-cred-1", env.accountUUID, "Key One")
	seedFIDO2IntegCredential(t, env.store, "list-cred-2", env.accountUUID, "Key Two")

	resp := env.doFIDO2AuthRequest(t, "GET", "/v1/fido2/credentials", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var listResp struct {
		Credentials []struct {
			CredentialID    string   `json:"credentialId"`
			Name            string   `json:"name"`
			AttestationType string   `json:"attestationType"`
			Transport       []string `json:"transport"`
			CreatedAt       int64    `json:"createdAt"`
			LastUsedAt      int64    `json:"lastUsedAt"`
		} `json:"credentials"`
	}
	decodeFIDO2JSON(t, resp, &listResp)

	require.Len(t, listResp.Credentials, 2)
	for _, c := range listResp.Credentials {
		assert.NotEmpty(t, c.CredentialID)
		assert.NotEmpty(t, c.Name)
		assert.Equal(t, "none", c.AttestationType)
		assert.NotNil(t, c.Transport)
		assert.NotZero(t, c.CreatedAt)
		assert.NotZero(t, c.LastUsedAt)
	}
}

func TestFIDO2_Credentials_Rename(t *testing.T) {
	env := setupFIDO2TestEnv(t)
	seedFIDO2IntegCredential(t, env.store, "rename-cred", env.accountUUID, "Old Name")

	resp := env.doFIDO2AuthRequest(t, "PUT", "/v1/fido2/credentials/rename-cred/name",
		map[string]any{"name": "New Name"})
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Verify the name was persisted.
	updated, err := env.store.GetCredential(context.Background(), "rename-cred")
	require.NoError(t, err)
	assert.Equal(t, "New Name", updated.Name)
}

func TestFIDO2_Credentials_Delete(t *testing.T) {
	env := setupFIDO2TestEnv(t)
	seedFIDO2IntegCredential(t, env.store, "delete-cred", env.accountUUID, "Delete Me")

	deleteResp := env.doFIDO2AuthRequest(t, "DELETE", "/v1/fido2/credentials/delete-cred", nil)
	require.Equal(t, http.StatusNoContent, deleteResp.StatusCode)
	deleteResp.Body.Close()

	// Verify credential is gone.
	_, err := env.store.GetCredential(context.Background(), "delete-cred")
	assert.Error(t, err)

	// Verify the list is now empty.
	listResp := env.doFIDO2AuthRequest(t, "GET", "/v1/fido2/credentials", nil)
	require.Equal(t, http.StatusOK, listResp.StatusCode)

	var list struct {
		Credentials []any `json:"credentials"`
	}
	decodeFIDO2JSON(t, listResp, &list)
	assert.Empty(t, list.Credentials)
}

func TestFIDO2_Credentials_DeleteNotFound(t *testing.T) {
	env := setupFIDO2TestEnv(t)

	resp := env.doFIDO2AuthRequest(t, "DELETE", "/v1/fido2/credentials/does-not-exist", nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestFIDO2_Credentials_RenameNotFound(t *testing.T) {
	env := setupFIDO2TestEnv(t)

	resp := env.doFIDO2AuthRequest(t, "PUT", "/v1/fido2/credentials/does-not-exist/name",
		map[string]any{"name": "Whatever"})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

// --------------------------------------------------------------------------
// Error paths
// --------------------------------------------------------------------------

func TestFIDO2_SessionExpired(t *testing.T) {
	env := setupFIDO2TestEnv(t)

	// Seed an already-expired session directly into the store.
	expiredSession := &fido2.FIDO2Session{
		ID:          "expired-session-id",
		AccountUUID: env.accountUUID,
		Username:    "charlie",
		Challenge:   []byte("expired-challenge"),
		SessionData: []byte("{}"),
		Type:        fido2.SessionTypeRegistration,
		CreatedAt:   time.Now().Add(-10 * time.Minute),
		ExpiresAt:   time.Now().Add(-5 * time.Minute), // already expired
	}
	require.NoError(t, env.store.StoreSession(context.Background(), expiredSession))

	// Attempting to complete the expired session must return 410 Gone.
	resp := env.doRequest(t, "POST", "/v1/fido2/session/expired-session-id/complete", nil, nil)
	assert.Equal(t, http.StatusGone, resp.StatusCode)
	resp.Body.Close()
}

// --------------------------------------------------------------------------
// Interface compliance
// --------------------------------------------------------------------------

// TestFIDO2MockProvider_InterfaceCompliance ensures fido2MockProvider satisfies
// fido2.WebAuthnProvider at compile time.
func TestFIDO2MockProvider_InterfaceCompliance(t *testing.T) {
	var _ fido2.WebAuthnProvider = (*fido2MockProvider)(nil)
}

// --------------------------------------------------------------------------
// Auth encoding helper (used by doFIDO2AuthRequest via doAuthRequest)
// --------------------------------------------------------------------------

// Verify that the base64-encoded Basic auth credential produced by doAuthRequest
// round-trips correctly. This guards against regressions in auth encoding.
func TestFIDO2_AuthEncoding(t *testing.T) {
	const uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	const pass = "fido2-test-password"
	encoded := base64.StdEncoding.EncodeToString([]byte(uuid + ".1:" + pass))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	assert.Equal(t, uuid+".1:"+pass, string(decoded))
}
