//go:build fido2

package fido2

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockWebAuthnProvider is a configurable mock for the WebAuthnProvider interface.
type mockWebAuthnProvider struct {
	beginRegistrationFn  func(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	finishRegistrationFn func(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
	beginLoginFn         func(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	finishLoginFn        func(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
}

func (m *mockWebAuthnProvider) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	if m.beginRegistrationFn != nil {
		return m.beginRegistrationFn(user, opts...)
	}
	return defaultMockCredentialCreation(), defaultMockSessionData(), nil
}

func (m *mockWebAuthnProvider) FinishRegistration(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	if m.finishRegistrationFn != nil {
		return m.finishRegistrationFn(user, session, response)
	}
	return defaultMockWebAuthnCredential(), nil
}

func (m *mockWebAuthnProvider) BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	if m.beginLoginFn != nil {
		return m.beginLoginFn(user, opts...)
	}
	return defaultMockCredentialAssertion(), defaultMockSessionData(), nil
}

func (m *mockWebAuthnProvider) FinishLogin(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	if m.finishLoginFn != nil {
		return m.finishLoginFn(user, session, response)
	}
	return defaultMockWebAuthnCredential(), nil
}

func defaultMockCredentialCreation() *protocol.CredentialCreation {
	return &protocol.CredentialCreation{
		Response: protocol.PublicKeyCredentialCreationOptions{
			Challenge: []byte("test-challenge"),
		},
	}
}

func defaultMockCredentialAssertion() *protocol.CredentialAssertion {
	return &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte("test-challenge"),
		},
	}
}

func defaultMockSessionData() *webauthn.SessionData {
	return &webauthn.SessionData{
		Challenge:      "dGVzdC1jaGFsbGVuZ2U",
		RelyingPartyID: "example.com",
		UserID:         []byte("test-user-id"),
	}
}

func defaultMockWebAuthnCredential() *webauthn.Credential {
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

func newTestManager(provider WebAuthnProvider) (*FIDO2AccountsManager, *MemoryFIDO2AccountsStore) {
	store := NewMemoryFIDO2AccountsStore()
	mgr := NewFIDO2AccountsManager(store, provider, FIDO2AccountsManagerConfig{
		SessionTimeout: 5 * time.Minute,
	})
	return mgr, store
}

func newTestManagerWithTimeout(provider WebAuthnProvider, timeout time.Duration) (*FIDO2AccountsManager, *MemoryFIDO2AccountsStore) {
	store := NewMemoryFIDO2AccountsStore()
	mgr := NewFIDO2AccountsManager(store, provider, FIDO2AccountsManagerConfig{
		SessionTimeout: timeout,
	})
	return mgr, store
}

// seedCredential creates and stores a credential in the given store, returning
// the base64url-encoded credential ID.
func seedCredential(t *testing.T, store *MemoryFIDO2AccountsStore, rawID []byte, accountUUID string) string {
	t.Helper()
	credID := base64.RawURLEncoding.EncodeToString(rawID)
	cred := &FIDO2Credential{
		CredentialID:    credID,
		AccountUUID:     accountUUID,
		Name:            "Seed Key",
		PublicKey:       []byte("pk-seed"),
		AttestationType: "none",
		AAGUID:          []byte{0x01, 0x02, 0x03, 0x04},
		SignCount:       0,
		Transport:       []string{"usb"},
		CreatedAt:       time.Now(),
		LastUsedAt:      time.Now(),
	}
	require.NoError(t, store.CreateCredential(context.Background(), cred))
	return credID
}

// --- Registration tests ---

func TestFIDO2AccountsManager_BeginRegistration_Success(t *testing.T) {
	mgr, _ := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	session, creation, err := mgr.BeginRegistration(ctx, "user-1", "alice")
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotNil(t, creation)

	assert.Equal(t, SessionTypeRegistration, session.Type)
	assert.Equal(t, "user-1", session.AccountUUID)
	assert.Equal(t, "alice", session.Username)
	assert.NotEmpty(t, session.ID)
	assert.NotEmpty(t, session.SessionData)
	assert.False(t, session.IsExpired())
}

func TestFIDO2AccountsManager_BeginRegistration_StoresSession(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	session, _, err := mgr.BeginRegistration(ctx, "user-1", "alice")
	require.NoError(t, err)

	retrieved, err := store.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, retrieved.ID)
	assert.Equal(t, SessionTypeRegistration, retrieved.Type)
	assert.Equal(t, "user-1", retrieved.AccountUUID)
}

func TestFIDO2AccountsManager_CompleteRegistration_Success(t *testing.T) {
	mgr, _ := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	session, _, err := mgr.BeginRegistration(ctx, "user-1", "alice")
	require.NoError(t, err)

	cred, err := mgr.CompleteRegistration(ctx, session.ID, &http.Request{})
	require.NoError(t, err)
	require.NotNil(t, cred)

	assert.Equal(t, "user-1", cred.AccountUUID)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString([]byte("test-credential-id")), cred.CredentialID)
	assert.Equal(t, []byte("test-public-key"), cred.PublicKey)
	assert.Equal(t, "none", cred.AttestationType)
	assert.Equal(t, []string{"usb"}, cred.Transport)
}

func TestFIDO2AccountsManager_CompleteRegistration_SessionNotFound(t *testing.T) {
	mgr, _ := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	_, err := mgr.CompleteRegistration(ctx, "nonexistent", &http.Request{})
	require.Error(t, err)

	var target *SessionNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.SessionID)
}

func TestFIDO2AccountsManager_CompleteRegistration_SessionExpired(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	session, _, err := mgr.BeginRegistration(ctx, "user-1", "alice")
	require.NoError(t, err)

	// Expire the session by updating it in the store.
	expired := &FIDO2Session{
		ID:          session.ID,
		AccountUUID: session.AccountUUID,
		Username:    session.Username,
		Challenge:   session.Challenge,
		SessionData: session.SessionData,
		Type:        SessionTypeRegistration,
		CreatedAt:   session.CreatedAt,
		ExpiresAt:   time.Now().Add(-1 * time.Minute),
	}
	require.NoError(t, store.StoreSession(ctx, expired))

	_, err = mgr.CompleteRegistration(ctx, session.ID, &http.Request{})
	require.Error(t, err)

	var target *SessionExpiredError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, session.ID, target.SessionID)
}

func TestFIDO2AccountsManager_CompleteRegistration_WrongSessionType(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	session, _, err := mgr.BeginRegistration(ctx, "user-1", "alice")
	require.NoError(t, err)

	// Change session type to Login.
	modified := &FIDO2Session{
		ID:          session.ID,
		AccountUUID: session.AccountUUID,
		Username:    session.Username,
		Challenge:   session.Challenge,
		SessionData: session.SessionData,
		Type:        SessionTypeLogin,
		CreatedAt:   session.CreatedAt,
		ExpiresAt:   session.ExpiresAt,
	}
	require.NoError(t, store.StoreSession(ctx, modified))

	_, err = mgr.CompleteRegistration(ctx, session.ID, &http.Request{})
	require.Error(t, err)

	var target *InvalidSessionTypeError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, SessionTypeRegistration, target.Expected)
	assert.Equal(t, SessionTypeLogin, target.Got)
}

// --- Enrollment tests ---

func TestFIDO2AccountsManager_BeginEnrollment_Success(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	// Seed an existing credential for the account.
	seedCredential(t, store, []byte("existing-cred"), "acct-1")

	session, creation, err := mgr.BeginEnrollment(ctx, "acct-1", "My YubiKey")
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotNil(t, creation)

	assert.Equal(t, SessionTypeEnrollment, session.Type)
	assert.Equal(t, "acct-1", session.AccountUUID)
	assert.Equal(t, "My YubiKey", session.Username)
	assert.NotEmpty(t, session.ID)
	assert.False(t, session.IsExpired())
}

func TestFIDO2AccountsManager_CompleteEnrollment_Success(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	seedCredential(t, store, []byte("existing-cred"), "acct-1")

	session, _, err := mgr.BeginEnrollment(ctx, "acct-1", "My YubiKey")
	require.NoError(t, err)

	cred, err := mgr.CompleteEnrollment(ctx, session.ID, &http.Request{})
	require.NoError(t, err)
	require.NotNil(t, cred)

	assert.Equal(t, "acct-1", cred.AccountUUID)
	assert.Equal(t, "My YubiKey", cred.Name)
	assert.NotEmpty(t, cred.CredentialID)

	// Verify the session was cleaned up.
	_, err = store.GetSession(ctx, session.ID)
	var target *SessionNotFoundError
	require.True(t, errors.As(err, &target))
}

// --- Login tests ---

func TestFIDO2AccountsManager_BeginLogin_Success(t *testing.T) {
	provider := &mockWebAuthnProvider{}
	mgr, store := newTestManager(provider)
	ctx := context.Background()

	seedCredential(t, store, []byte("test-credential-id"), "acct-1")

	session, assertion, err := mgr.BeginLogin(ctx, "acct-1")
	require.NoError(t, err)
	require.NotNil(t, session)
	require.NotNil(t, assertion)

	assert.Equal(t, SessionTypeLogin, session.Type)
	assert.Equal(t, "acct-1", session.AccountUUID)
	assert.NotEmpty(t, session.ID)
	assert.False(t, session.IsExpired())
}

func TestFIDO2AccountsManager_BeginLogin_NoCredentials(t *testing.T) {
	mgr, _ := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	_, _, err := mgr.BeginLogin(ctx, "acct-no-creds")
	require.Error(t, err)

	var target *NoCredentialsError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "acct-no-creds", target.AccountUUID)
}

func TestFIDO2AccountsManager_CompleteLogin_Success(t *testing.T) {
	mockCred := defaultMockWebAuthnCredential()
	mockCred.Authenticator.SignCount = 5
	provider := &mockWebAuthnProvider{
		finishLoginFn: func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
			return mockCred, nil
		},
	}
	mgr, store := newTestManager(provider)
	ctx := context.Background()

	seedCredential(t, store, []byte("test-credential-id"), "acct-1")

	session, _, err := mgr.BeginLogin(ctx, "acct-1")
	require.NoError(t, err)

	accountUUID, err := mgr.CompleteLogin(ctx, session.ID, &http.Request{})
	require.NoError(t, err)
	assert.Equal(t, "acct-1", accountUUID)

	// Verify sign count was updated.
	credID := base64.RawURLEncoding.EncodeToString([]byte("test-credential-id"))
	updated, err := store.GetCredential(ctx, credID)
	require.NoError(t, err)
	assert.Equal(t, uint32(5), updated.SignCount)

	// Verify the session was cleaned up.
	_, err = store.GetSession(ctx, session.ID)
	var target *SessionNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestFIDO2AccountsManager_CompleteLogin_SessionExpired(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	seedCredential(t, store, []byte("test-credential-id"), "acct-1")

	session, _, err := mgr.BeginLogin(ctx, "acct-1")
	require.NoError(t, err)

	// Expire the session.
	expired := &FIDO2Session{
		ID:          session.ID,
		AccountUUID: session.AccountUUID,
		Username:    session.Username,
		Challenge:   session.Challenge,
		SessionData: session.SessionData,
		Type:        SessionTypeLogin,
		CreatedAt:   session.CreatedAt,
		ExpiresAt:   time.Now().Add(-1 * time.Minute),
	}
	require.NoError(t, store.StoreSession(ctx, expired))

	_, err = mgr.CompleteLogin(ctx, session.ID, &http.Request{})
	require.Error(t, err)

	var target *SessionExpiredError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, session.ID, target.SessionID)
}

// --- Management method tests ---

func TestFIDO2AccountsManager_ListCredentials_Success(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	seedCredential(t, store, []byte("cred-1"), "acct-1")
	seedCredential(t, store, []byte("cred-2"), "acct-1")

	creds, err := mgr.ListCredentials(ctx, "acct-1")
	require.NoError(t, err)
	assert.Len(t, creds, 2)
}

func TestFIDO2AccountsManager_ListCredentials_Empty(t *testing.T) {
	mgr, _ := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	creds, err := mgr.ListCredentials(ctx, "acct-no-creds")
	require.NoError(t, err)
	assert.Empty(t, creds)
	assert.NotNil(t, creds)
}

func TestFIDO2AccountsManager_DeleteCredential_Success(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	credID := seedCredential(t, store, []byte("to-delete"), "acct-1")

	err := mgr.DeleteCredential(ctx, "acct-1", credID)
	require.NoError(t, err)

	_, err = store.GetCredential(ctx, credID)
	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestFIDO2AccountsManager_DeleteCredential_NotFound(t *testing.T) {
	mgr, _ := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	err := mgr.DeleteCredential(ctx, "acct-1", "nonexistent")
	require.Error(t, err)

	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestFIDO2AccountsManager_RenameCredential_Success(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	credID := seedCredential(t, store, []byte("to-rename"), "acct-1")

	err := mgr.RenameCredential(ctx, "acct-1", credID, "New Name")
	require.NoError(t, err)

	updated, err := store.GetCredential(ctx, credID)
	require.NoError(t, err)
	assert.Equal(t, "New Name", updated.Name)
}

func TestFIDO2AccountsManager_HasCredentials_True(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	seedCredential(t, store, []byte("has-cred"), "acct-1")

	has, err := mgr.HasCredentials(ctx, "acct-1")
	require.NoError(t, err)
	assert.True(t, has)
}

func TestFIDO2AccountsManager_HasCredentials_False(t *testing.T) {
	mgr, _ := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	has, err := mgr.HasCredentials(ctx, "acct-no-creds")
	require.NoError(t, err)
	assert.False(t, has)
}

// --- Default session timeout test ---

func TestFIDO2AccountsManager_DefaultSessionTimeout(t *testing.T) {
	store := NewMemoryFIDO2AccountsStore()
	mgr := NewFIDO2AccountsManager(store, &mockWebAuthnProvider{}, FIDO2AccountsManagerConfig{})
	ctx := context.Background()

	session, _, err := mgr.BeginRegistration(ctx, "user-1", "alice")
	require.NoError(t, err)

	// The default timeout is 60 seconds; session should expire roughly
	// 60 seconds from now.
	expectedExpiry := time.Now().Add(defaultSessionTimeout)
	assert.WithinDuration(t, expectedExpiry, session.ExpiresAt, 2*time.Second)
}

// --- GetSession test ---

func TestFIDO2AccountsManager_GetSession_Success(t *testing.T) {
	mgr, _ := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	session, _, err := mgr.BeginRegistration(ctx, "user-1", "alice")
	require.NoError(t, err)

	retrieved, err := mgr.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, retrieved.ID)
	assert.Equal(t, SessionTypeRegistration, retrieved.Type)
}

func TestFIDO2AccountsManager_GetSession_NotFound(t *testing.T) {
	mgr, _ := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	_, err := mgr.GetSession(ctx, "nonexistent")
	require.Error(t, err)

	var target *SessionNotFoundError
	require.True(t, errors.As(err, &target))
}

// --- DeleteCredential account mismatch test ---

func TestFIDO2AccountsManager_DeleteCredential_WrongAccount(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	credID := seedCredential(t, store, []byte("owned-by-other"), "acct-2")

	err := mgr.DeleteCredential(ctx, "acct-1", credID)
	require.Error(t, err)

	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
}

// --- RenameCredential error tests ---

func TestFIDO2AccountsManager_RenameCredential_NotFound(t *testing.T) {
	mgr, _ := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	err := mgr.RenameCredential(ctx, "acct-1", "nonexistent", "New Name")
	require.Error(t, err)

	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestFIDO2AccountsManager_RenameCredential_WrongAccount(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	credID := seedCredential(t, store, []byte("owned-by-other"), "acct-2")

	err := mgr.RenameCredential(ctx, "acct-1", credID, "New Name")
	require.Error(t, err)

	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
}

// --- Provider error propagation tests ---

func TestFIDO2AccountsManager_BeginRegistration_ProviderError(t *testing.T) {
	providerErr := errors.New("provider failure")
	provider := &mockWebAuthnProvider{
		beginRegistrationFn: func(_ webauthn.User, _ ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
			return nil, nil, providerErr
		},
	}
	mgr, _ := newTestManager(provider)
	ctx := context.Background()

	_, _, err := mgr.BeginRegistration(ctx, "user-1", "alice")
	require.Error(t, err)

	var target *CeremonyError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "begin_registration", target.Phase)
	assert.ErrorIs(t, target.Cause, providerErr)
}

func TestFIDO2AccountsManager_CompleteRegistration_ProviderError(t *testing.T) {
	providerErr := errors.New("finish failed")
	provider := &mockWebAuthnProvider{
		finishRegistrationFn: func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
			return nil, providerErr
		},
	}
	mgr, _ := newTestManager(provider)
	ctx := context.Background()

	session, _, err := mgr.BeginRegistration(ctx, "user-1", "alice")
	require.NoError(t, err)

	_, err = mgr.CompleteRegistration(ctx, session.ID, &http.Request{})
	require.Error(t, err)

	var target *CeremonyError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "complete_registration", target.Phase)
}

func TestFIDO2AccountsManager_BeginLogin_ProviderError(t *testing.T) {
	providerErr := errors.New("login provider failure")
	provider := &mockWebAuthnProvider{
		beginLoginFn: func(_ webauthn.User, _ ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
			return nil, nil, providerErr
		},
	}
	mgr, store := newTestManager(provider)
	ctx := context.Background()

	seedCredential(t, store, []byte("cred-1"), "acct-1")

	_, _, err := mgr.BeginLogin(ctx, "acct-1")
	require.Error(t, err)

	var target *CeremonyError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "begin_login", target.Phase)
}

func TestFIDO2AccountsManager_CompleteLogin_ProviderError(t *testing.T) {
	providerErr := errors.New("finish login failed")
	callCount := 0
	provider := &mockWebAuthnProvider{
		finishLoginFn: func(_ webauthn.User, _ webauthn.SessionData, _ *http.Request) (*webauthn.Credential, error) {
			callCount++
			return nil, providerErr
		},
	}
	mgr, store := newTestManager(provider)
	ctx := context.Background()

	seedCredential(t, store, []byte("test-credential-id"), "acct-1")

	session, _, err := mgr.BeginLogin(ctx, "acct-1")
	require.NoError(t, err)

	_, err = mgr.CompleteLogin(ctx, session.ID, &http.Request{})
	require.Error(t, err)

	var target *CeremonyError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "complete_login", target.Phase)
}

// --- Enrollment with empty name defaults ---

func TestFIDO2AccountsManager_CompleteEnrollment_DefaultName(t *testing.T) {
	mgr, store := newTestManager(&mockWebAuthnProvider{})
	ctx := context.Background()

	seedCredential(t, store, []byte("existing-cred"), "acct-1")

	// Begin enrollment with empty credential name.
	session, _, err := mgr.BeginEnrollment(ctx, "acct-1", "")
	require.NoError(t, err)

	cred, err := mgr.CompleteEnrollment(ctx, session.ID, &http.Request{})
	require.NoError(t, err)
	assert.Equal(t, "FIDO2 Key", cred.Name)
}

// --- WebAuthnUserWithCredentials test ---

func TestFIDO2AccountsManager_WebAuthnUserWithCredentials(t *testing.T) {
	creds := []webauthn.Credential{
		{ID: []byte("cred-1"), PublicKey: []byte("pk-1")},
		{ID: []byte("cred-2"), PublicKey: []byte("pk-2")},
	}
	user := &webAuthnUserWithCredentials{
		WebAuthnUser: &WebAuthnUser{
			ID:          []byte("user-1"),
			Name:        "alice",
			DisplayName: "Alice",
		},
		credentials: creds,
	}

	assert.Equal(t, []byte("user-1"), user.WebAuthnID())
	assert.Equal(t, "alice", user.WebAuthnName())
	assert.Equal(t, "Alice", user.WebAuthnDisplayName())
	assert.Len(t, user.WebAuthnCredentials(), 2)
}

// --- Interface compliance ---

func TestFIDO2AccountsManager_ProviderInterfaceCompliance(t *testing.T) {
	var _ WebAuthnProvider = (*mockWebAuthnProvider)(nil)
	var _ WebAuthnProvider = (*DefaultWebAuthnProvider)(nil)
}
