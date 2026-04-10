//go:build fido2

package fido2

// CredentialNotFoundError indicates that the requested FIDO2 credential does
// not exist in the store.
type CredentialNotFoundError struct {
	CredentialID string
}

func (e *CredentialNotFoundError) Error() string {
	return "fido2 credential not found: " + e.CredentialID
}

// CredentialExistsError indicates that a FIDO2 credential with the given ID
// already exists.
type CredentialExistsError struct {
	CredentialID string
}

func (e *CredentialExistsError) Error() string {
	return "fido2 credential already exists: " + e.CredentialID
}

// SessionNotFoundError indicates that the requested WebAuthn session does not
// exist in the store.
type SessionNotFoundError struct {
	SessionID string
}

func (e *SessionNotFoundError) Error() string {
	return "fido2 session not found: " + e.SessionID
}

// SessionExpiredError indicates that the WebAuthn session has expired.
type SessionExpiredError struct {
	SessionID string
}

func (e *SessionExpiredError) Error() string {
	return "fido2 session expired: " + e.SessionID
}

// NoCredentialsError indicates that the account has no registered FIDO2
// credentials.
type NoCredentialsError struct {
	AccountUUID string
}

func (e *NoCredentialsError) Error() string {
	return "no fido2 credentials for account: " + e.AccountUUID
}

// CeremonyError indicates a failure during a WebAuthn ceremony phase.
type CeremonyError struct {
	SessionID string
	Phase     string
	Cause     error
}

func (e *CeremonyError) Error() string {
	msg := "fido2 ceremony error in " + e.Phase + " for session " + e.SessionID
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying cause of the ceremony error.
func (e *CeremonyError) Unwrap() error {
	return e.Cause
}

// InvalidSessionTypeError indicates a session type mismatch during a WebAuthn
// ceremony.
type InvalidSessionTypeError struct {
	Expected FIDO2SessionType
	Got      FIDO2SessionType
}

func (e *InvalidSessionTypeError) Error() string {
	return "invalid fido2 session type: expected " + string(e.Expected) + ", got " + string(e.Got)
}
