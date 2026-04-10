//go:build fido2

package fido2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

const defaultSessionTimeout = 60 * time.Second

// FIDO2AccountsManagerConfig configures the FIDO2 accounts manager.
type FIDO2AccountsManagerConfig struct {
	SessionTimeout time.Duration // default 60s
}

// FIDO2AccountsManager handles WebAuthn ceremony flows and credential management.
type FIDO2AccountsManager struct {
	store    FIDO2AccountsStore
	provider WebAuthnProvider
	config   FIDO2AccountsManagerConfig
}

// NewFIDO2AccountsManager creates a new FIDO2AccountsManager with the given
// store, WebAuthn provider, and configuration.
func NewFIDO2AccountsManager(store FIDO2AccountsStore, provider WebAuthnProvider, config FIDO2AccountsManagerConfig) *FIDO2AccountsManager {
	if config.SessionTimeout <= 0 {
		config.SessionTimeout = defaultSessionTimeout
	}
	return &FIDO2AccountsManager{
		store:    store,
		provider: provider,
		config:   config,
	}
}

// webAuthnUserWithCredentials wraps a WebAuthnUser and adds credential support
// to satisfy the webauthn.User interface.
type webAuthnUserWithCredentials struct {
	*WebAuthnUser
	credentials []webauthn.Credential
}

// WebAuthnCredentials returns the credentials associated with this user.
func (u *webAuthnUserWithCredentials) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}

// BeginRegistration starts a new FIDO2 registration ceremony for a new account.
func (m *FIDO2AccountsManager) BeginRegistration(ctx context.Context, userID, username string) (*FIDO2Session, *protocol.CredentialCreation, error) {
	user := &webAuthnUserWithCredentials{
		WebAuthnUser: &WebAuthnUser{
			ID:          []byte(userID),
			Name:        username,
			DisplayName: username,
		},
	}

	creation, sessionData, err := m.provider.BeginRegistration(user)
	if err != nil {
		return nil, nil, &CeremonyError{
			Phase: "begin_registration",
			Cause: err,
		}
	}

	serialized, err := json.Marshal(sessionData)
	if err != nil {
		return nil, nil, &CeremonyError{
			Phase: "begin_registration",
			Cause: err,
		}
	}

	now := time.Now()
	session := &FIDO2Session{
		ID:          uuid.New().String(),
		AccountUUID: userID,
		Username:    username,
		Challenge:   []byte(sessionData.Challenge),
		SessionData: serialized,
		Type:        SessionTypeRegistration,
		CreatedAt:   now,
		ExpiresAt:   now.Add(m.config.SessionTimeout),
	}

	if err := m.store.StoreSession(ctx, session); err != nil {
		return nil, nil, &CeremonyError{
			SessionID: session.ID,
			Phase:     "begin_registration",
			Cause:     err,
		}
	}

	return session, creation, nil
}

// CompleteRegistration finishes a registration ceremony and stores the new credential.
func (m *FIDO2AccountsManager) CompleteRegistration(ctx context.Context, sessionID string, r *http.Request) (*FIDO2Credential, error) {
	session, err := m.getValidatedSession(ctx, sessionID, SessionTypeRegistration)
	if err != nil {
		return nil, err
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(session.SessionData, &sessionData); err != nil {
		return nil, &CeremonyError{
			SessionID: sessionID,
			Phase:     "complete_registration",
			Cause:     err,
		}
	}

	user := &webAuthnUserWithCredentials{
		WebAuthnUser: &WebAuthnUser{
			ID:          []byte(session.AccountUUID),
			Name:        session.Username,
			DisplayName: session.Username,
		},
	}

	waCred, err := m.provider.FinishRegistration(user, sessionData, r)
	if err != nil {
		return nil, &CeremonyError{
			SessionID: sessionID,
			Phase:     "complete_registration",
			Cause:     err,
		}
	}

	cred := webAuthnToCredential(waCred, session.AccountUUID, "")

	if err := m.store.CreateCredential(ctx, cred); err != nil {
		return nil, &CeremonyError{
			SessionID: sessionID,
			Phase:     "complete_registration",
			Cause:     err,
		}
	}

	// Best-effort session cleanup.
	_ = m.store.DeleteSession(ctx, sessionID)

	return cred, nil
}

// BeginEnrollment starts an enrollment ceremony for adding a FIDO2 credential
// to an existing account (MFA).
func (m *FIDO2AccountsManager) BeginEnrollment(ctx context.Context, accountUUID, credentialName string) (*FIDO2Session, *protocol.CredentialCreation, error) {
	existingCreds, err := m.store.GetCredentialsByAccount(ctx, accountUUID)
	if err != nil {
		return nil, nil, &CeremonyError{
			Phase: "begin_enrollment",
			Cause: err,
		}
	}

	waCredentials := credentialsToWebAuthn(existingCreds)

	user := &webAuthnUserWithCredentials{
		WebAuthnUser: &WebAuthnUser{
			ID:          []byte(accountUUID),
			Name:        accountUUID,
			DisplayName: accountUUID,
		},
		credentials: waCredentials,
	}

	// Build exclude list from existing credentials.
	excludeList := make([]protocol.CredentialDescriptor, len(waCredentials))
	for i, c := range waCredentials {
		excludeList[i] = protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
			Transport:    c.Transport,
		}
	}

	creation, sessionData, err := m.provider.BeginRegistration(user, webauthn.WithExclusions(excludeList))
	if err != nil {
		return nil, nil, &CeremonyError{
			Phase: "begin_enrollment",
			Cause: err,
		}
	}

	serialized, err := json.Marshal(sessionData)
	if err != nil {
		return nil, nil, &CeremonyError{
			Phase: "begin_enrollment",
			Cause: err,
		}
	}

	now := time.Now()
	session := &FIDO2Session{
		ID:          uuid.New().String(),
		AccountUUID: accountUUID,
		Username:    credentialName,
		Challenge:   []byte(sessionData.Challenge),
		SessionData: serialized,
		Type:        SessionTypeEnrollment,
		CreatedAt:   now,
		ExpiresAt:   now.Add(m.config.SessionTimeout),
	}

	if err := m.store.StoreSession(ctx, session); err != nil {
		return nil, nil, &CeremonyError{
			SessionID: session.ID,
			Phase:     "begin_enrollment",
			Cause:     err,
		}
	}

	return session, creation, nil
}

// CompleteEnrollment finishes an enrollment ceremony and stores the new credential.
func (m *FIDO2AccountsManager) CompleteEnrollment(ctx context.Context, sessionID string, r *http.Request) (*FIDO2Credential, error) {
	session, err := m.getValidatedSession(ctx, sessionID, SessionTypeEnrollment)
	if err != nil {
		return nil, err
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(session.SessionData, &sessionData); err != nil {
		return nil, &CeremonyError{
			SessionID: sessionID,
			Phase:     "complete_enrollment",
			Cause:     err,
		}
	}

	user := &webAuthnUserWithCredentials{
		WebAuthnUser: &WebAuthnUser{
			ID:          []byte(session.AccountUUID),
			Name:        session.AccountUUID,
			DisplayName: session.AccountUUID,
		},
	}

	waCred, err := m.provider.FinishRegistration(user, sessionData, r)
	if err != nil {
		return nil, &CeremonyError{
			SessionID: sessionID,
			Phase:     "complete_enrollment",
			Cause:     err,
		}
	}

	name := session.Username
	if name == "" {
		name = "FIDO2 Key"
	}

	cred := webAuthnToCredential(waCred, session.AccountUUID, name)

	if err := m.store.CreateCredential(ctx, cred); err != nil {
		return nil, &CeremonyError{
			SessionID: sessionID,
			Phase:     "complete_enrollment",
			Cause:     err,
		}
	}

	// Best-effort session cleanup.
	_ = m.store.DeleteSession(ctx, sessionID)

	return cred, nil
}

// BeginLogin starts a login ceremony for the given account.
func (m *FIDO2AccountsManager) BeginLogin(ctx context.Context, accountUUID string) (*FIDO2Session, *protocol.CredentialAssertion, error) {
	existingCreds, err := m.store.GetCredentialsByAccount(ctx, accountUUID)
	if err != nil {
		return nil, nil, &CeremonyError{
			Phase: "begin_login",
			Cause: err,
		}
	}

	if len(existingCreds) == 0 {
		return nil, nil, &NoCredentialsError{AccountUUID: accountUUID}
	}

	waCredentials := credentialsToWebAuthn(existingCreds)

	user := &webAuthnUserWithCredentials{
		WebAuthnUser: &WebAuthnUser{
			ID:          []byte(accountUUID),
			Name:        accountUUID,
			DisplayName: accountUUID,
		},
		credentials: waCredentials,
	}

	assertion, sessionData, err := m.provider.BeginLogin(user)
	if err != nil {
		return nil, nil, &CeremonyError{
			Phase: "begin_login",
			Cause: err,
		}
	}

	serialized, err := json.Marshal(sessionData)
	if err != nil {
		return nil, nil, &CeremonyError{
			Phase: "begin_login",
			Cause: err,
		}
	}

	now := time.Now()
	session := &FIDO2Session{
		ID:          uuid.New().String(),
		AccountUUID: accountUUID,
		Challenge:   []byte(sessionData.Challenge),
		SessionData: serialized,
		Type:        SessionTypeLogin,
		CreatedAt:   now,
		ExpiresAt:   now.Add(m.config.SessionTimeout),
	}

	if err := m.store.StoreSession(ctx, session); err != nil {
		return nil, nil, &CeremonyError{
			SessionID: session.ID,
			Phase:     "begin_login",
			Cause:     err,
		}
	}

	return session, assertion, nil
}

// CompleteLogin finishes a login ceremony, updates the credential sign count,
// and returns the account UUID.
func (m *FIDO2AccountsManager) CompleteLogin(ctx context.Context, sessionID string, r *http.Request) (string, error) {
	session, err := m.getValidatedSession(ctx, sessionID, SessionTypeLogin)
	if err != nil {
		return "", err
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(session.SessionData, &sessionData); err != nil {
		return "", &CeremonyError{
			SessionID: sessionID,
			Phase:     "complete_login",
			Cause:     err,
		}
	}

	existingCreds, err := m.store.GetCredentialsByAccount(ctx, session.AccountUUID)
	if err != nil {
		return "", &CeremonyError{
			SessionID: sessionID,
			Phase:     "complete_login",
			Cause:     err,
		}
	}

	waCredentials := credentialsToWebAuthn(existingCreds)

	user := &webAuthnUserWithCredentials{
		WebAuthnUser: &WebAuthnUser{
			ID:          []byte(session.AccountUUID),
			Name:        session.AccountUUID,
			DisplayName: session.AccountUUID,
		},
		credentials: waCredentials,
	}

	waCred, err := m.provider.FinishLogin(user, sessionData, r)
	if err != nil {
		return "", &CeremonyError{
			SessionID: sessionID,
			Phase:     "complete_login",
			Cause:     err,
		}
	}

	// Update sign count and last used time on the matched credential.
	credID := base64.RawURLEncoding.EncodeToString(waCred.ID)
	for _, c := range existingCreds {
		if c.CredentialID == credID {
			c.SignCount = waCred.Authenticator.SignCount
			c.CloneWarning = waCred.Authenticator.CloneWarning
			c.LastUsedAt = time.Now()
			if err := m.store.UpdateCredential(ctx, c); err != nil {
				return "", &CeremonyError{
					SessionID: sessionID,
					Phase:     "complete_login",
					Cause:     err,
				}
			}
			break
		}
	}

	// Best-effort session cleanup.
	_ = m.store.DeleteSession(ctx, sessionID)

	return session.AccountUUID, nil
}

// GetSession retrieves a session by its unique identifier.
func (m *FIDO2AccountsManager) GetSession(ctx context.Context, sessionID string) (*FIDO2Session, error) {
	return m.store.GetSession(ctx, sessionID)
}

// ListCredentials returns all credentials for the given account.
func (m *FIDO2AccountsManager) ListCredentials(ctx context.Context, accountUUID string) ([]*FIDO2Credential, error) {
	return m.store.GetCredentialsByAccount(ctx, accountUUID)
}

// DeleteCredential removes a credential from the given account.
func (m *FIDO2AccountsManager) DeleteCredential(ctx context.Context, accountUUID, credentialID string) error {
	cred, err := m.store.GetCredential(ctx, credentialID)
	if err != nil {
		return err
	}
	if cred.AccountUUID != accountUUID {
		return &CredentialNotFoundError{CredentialID: credentialID}
	}
	return m.store.DeleteCredential(ctx, credentialID)
}

// RenameCredential updates the name of a credential belonging to the given account.
func (m *FIDO2AccountsManager) RenameCredential(ctx context.Context, accountUUID, credentialID, name string) error {
	cred, err := m.store.GetCredential(ctx, credentialID)
	if err != nil {
		return err
	}
	if cred.AccountUUID != accountUUID {
		return &CredentialNotFoundError{CredentialID: credentialID}
	}
	cred.Name = name
	return m.store.UpdateCredential(ctx, cred)
}

// HasCredentials reports whether the given account has any registered FIDO2
// credentials.
func (m *FIDO2AccountsManager) HasCredentials(ctx context.Context, accountUUID string) (bool, error) {
	creds, err := m.store.GetCredentialsByAccount(ctx, accountUUID)
	if err != nil {
		return false, err
	}
	return len(creds) > 0, nil
}

// getValidatedSession retrieves a session, validates its type and expiration.
func (m *FIDO2AccountsManager) getValidatedSession(ctx context.Context, sessionID string, expectedType FIDO2SessionType) (*FIDO2Session, error) {
	session, err := m.store.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if session.Type != expectedType {
		return nil, &InvalidSessionTypeError{
			Expected: expectedType,
			Got:      session.Type,
		}
	}

	if session.IsExpired() {
		return nil, &SessionExpiredError{SessionID: sessionID}
	}

	return session, nil
}

// credentialToWebAuthn converts a FIDO2Credential to a webauthn.Credential.
func credentialToWebAuthn(cred *FIDO2Credential) webauthn.Credential {
	idBytes, _ := base64.RawURLEncoding.DecodeString(cred.CredentialID)

	transports := make([]protocol.AuthenticatorTransport, len(cred.Transport))
	for i, t := range cred.Transport {
		transports[i] = protocol.AuthenticatorTransport(t)
	}

	return webauthn.Credential{
		ID:              idBytes,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		Transport:       transports,
		Authenticator: webauthn.Authenticator{
			AAGUID:       cred.AAGUID,
			SignCount:    cred.SignCount,
			CloneWarning: cred.CloneWarning,
		},
	}
}

// credentialsToWebAuthn converts a slice of FIDO2Credential pointers to a
// slice of webauthn.Credential values.
func credentialsToWebAuthn(creds []*FIDO2Credential) []webauthn.Credential {
	result := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		result[i] = credentialToWebAuthn(c)
	}
	return result
}

// webAuthnToCredential converts a webauthn.Credential to a FIDO2Credential
// with the given account UUID and name.
func webAuthnToCredential(waCred *webauthn.Credential, accountUUID, name string) *FIDO2Credential {
	transports := make([]string, len(waCred.Transport))
	for i, t := range waCred.Transport {
		transports[i] = string(t)
	}

	now := time.Now()
	return &FIDO2Credential{
		CredentialID:    base64.RawURLEncoding.EncodeToString(waCred.ID),
		AccountUUID:     accountUUID,
		Name:            name,
		PublicKey:       waCred.PublicKey,
		AttestationType: waCred.AttestationType,
		AAGUID:          waCred.Authenticator.AAGUID,
		SignCount:       waCred.Authenticator.SignCount,
		CloneWarning:    waCred.Authenticator.CloneWarning,
		Transport:       transports,
		CreatedAt:       now,
		LastUsedAt:      now,
	}
}
