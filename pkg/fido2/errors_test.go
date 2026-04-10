//go:build fido2

package fido2

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- CredentialNotFoundError tests ---

func TestCredentialNotFoundError_Error(t *testing.T) {
	e := &CredentialNotFoundError{CredentialID: "cred-abc"}
	assert.Equal(t, "fido2 credential not found: cred-abc", e.Error())
}

func TestCredentialNotFoundError_ImplementsError(t *testing.T) {
	var _ error = (*CredentialNotFoundError)(nil)
}

func TestCredentialNotFoundError_ErrorsAs(t *testing.T) {
	var err error = &CredentialNotFoundError{CredentialID: "cred-1"}
	var target *CredentialNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "cred-1", target.CredentialID)
}

// --- CredentialExistsError tests ---

func TestCredentialExistsError_Error(t *testing.T) {
	e := &CredentialExistsError{CredentialID: "cred-xyz"}
	assert.Equal(t, "fido2 credential already exists: cred-xyz", e.Error())
}

func TestCredentialExistsError_ImplementsError(t *testing.T) {
	var _ error = (*CredentialExistsError)(nil)
}

func TestCredentialExistsError_ErrorsAs(t *testing.T) {
	var err error = &CredentialExistsError{CredentialID: "cred-2"}
	var target *CredentialExistsError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "cred-2", target.CredentialID)
}

// --- SessionNotFoundError tests ---

func TestSessionNotFoundError_Error(t *testing.T) {
	e := &SessionNotFoundError{SessionID: "sess-abc"}
	assert.Equal(t, "fido2 session not found: sess-abc", e.Error())
}

func TestSessionNotFoundError_ImplementsError(t *testing.T) {
	var _ error = (*SessionNotFoundError)(nil)
}

func TestSessionNotFoundError_ErrorsAs(t *testing.T) {
	var err error = &SessionNotFoundError{SessionID: "sess-1"}
	var target *SessionNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "sess-1", target.SessionID)
}

// --- SessionExpiredError tests ---

func TestSessionExpiredError_Error(t *testing.T) {
	e := &SessionExpiredError{SessionID: "sess-expired"}
	assert.Equal(t, "fido2 session expired: sess-expired", e.Error())
}

func TestSessionExpiredError_ImplementsError(t *testing.T) {
	var _ error = (*SessionExpiredError)(nil)
}

func TestSessionExpiredError_ErrorsAs(t *testing.T) {
	var err error = &SessionExpiredError{SessionID: "sess-2"}
	var target *SessionExpiredError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "sess-2", target.SessionID)
}

// --- NoCredentialsError tests ---

func TestNoCredentialsError_Error(t *testing.T) {
	e := &NoCredentialsError{AccountUUID: "acct-123"}
	assert.Equal(t, "no fido2 credentials for account: acct-123", e.Error())
}

func TestNoCredentialsError_ImplementsError(t *testing.T) {
	var _ error = (*NoCredentialsError)(nil)
}

func TestNoCredentialsError_ErrorsAs(t *testing.T) {
	var err error = &NoCredentialsError{AccountUUID: "acct-1"}
	var target *NoCredentialsError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "acct-1", target.AccountUUID)
}

// --- CeremonyError tests ---

func TestCeremonyError_Error_WithCause(t *testing.T) {
	cause := errors.New("invalid signature")
	e := &CeremonyError{
		SessionID: "sess-1",
		Phase:     "assertion",
		Cause:     cause,
	}
	assert.Equal(t, "fido2 ceremony error in assertion for session sess-1: invalid signature", e.Error())
}

func TestCeremonyError_Error_WithoutCause(t *testing.T) {
	e := &CeremonyError{
		SessionID: "sess-1",
		Phase:     "attestation",
		Cause:     nil,
	}
	assert.Equal(t, "fido2 ceremony error in attestation for session sess-1", e.Error())
}

func TestCeremonyError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	e := &CeremonyError{
		SessionID: "sess-1",
		Phase:     "verification",
		Cause:     cause,
	}
	assert.Equal(t, cause, e.Unwrap())
}

func TestCeremonyError_Unwrap_Nil(t *testing.T) {
	e := &CeremonyError{
		SessionID: "sess-1",
		Phase:     "verification",
		Cause:     nil,
	}
	assert.Nil(t, e.Unwrap())
}

func TestCeremonyError_ImplementsError(t *testing.T) {
	var _ error = (*CeremonyError)(nil)
}

func TestCeremonyError_ErrorsIs(t *testing.T) {
	cause := errors.New("root cause")
	e := &CeremonyError{
		SessionID: "sess-1",
		Phase:     "challenge",
		Cause:     cause,
	}
	require.True(t, errors.Is(e, cause))
}

// --- InvalidSessionTypeError tests ---

func TestInvalidSessionTypeError_Error(t *testing.T) {
	e := &InvalidSessionTypeError{
		Expected: SessionTypeRegistration,
		Got:      SessionTypeLogin,
	}
	assert.Equal(t, "invalid fido2 session type: expected registration, got login", e.Error())
}

func TestInvalidSessionTypeError_ImplementsError(t *testing.T) {
	var _ error = (*InvalidSessionTypeError)(nil)
}

func TestInvalidSessionTypeError_ErrorsAs(t *testing.T) {
	var err error = &InvalidSessionTypeError{
		Expected: SessionTypeEnrollment,
		Got:      SessionTypeRegistration,
	}
	var target *InvalidSessionTypeError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, SessionTypeEnrollment, target.Expected)
	assert.Equal(t, SessionTypeRegistration, target.Got)
}
