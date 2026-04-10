//go:build fido2

package fido2

import "context"

// FIDO2AccountsStore persists FIDO2 credentials and WebAuthn ceremony sessions.
type FIDO2AccountsStore interface {
	// CreateCredential stores a new FIDO2 credential. It returns a
	// CredentialExistsError if a credential with the same ID already exists.
	CreateCredential(ctx context.Context, cred *FIDO2Credential) error

	// GetCredential retrieves a credential by its unique identifier. It returns
	// a CredentialNotFoundError if no credential with the given ID exists.
	GetCredential(ctx context.Context, credentialID string) (*FIDO2Credential, error)

	// GetCredentialsByAccount returns all credentials registered to the given
	// account. It returns an empty slice if the account has no credentials.
	GetCredentialsByAccount(ctx context.Context, accountUUID string) ([]*FIDO2Credential, error)

	// UpdateCredential overwrites an existing credential. It returns a
	// CredentialNotFoundError if the credential does not exist.
	UpdateCredential(ctx context.Context, cred *FIDO2Credential) error

	// DeleteCredential removes a credential by its unique identifier. It returns
	// a CredentialNotFoundError if no credential with the given ID exists.
	DeleteCredential(ctx context.Context, credentialID string) error

	// StoreSession persists a WebAuthn ceremony session.
	StoreSession(ctx context.Context, session *FIDO2Session) error

	// GetSession retrieves a session by its unique identifier. It returns a
	// SessionNotFoundError if no session with the given ID exists.
	GetSession(ctx context.Context, sessionID string) (*FIDO2Session, error)

	// DeleteSession removes a session by its unique identifier. It returns a
	// SessionNotFoundError if no session with the given ID exists.
	DeleteSession(ctx context.Context, sessionID string) error
}
