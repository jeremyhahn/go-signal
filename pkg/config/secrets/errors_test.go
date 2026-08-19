package secrets

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolverNotFoundError_Error(t *testing.T) {
	err := &ResolverNotFoundError{Scheme: "kms"}
	assert.Equal(t, "secrets: no resolver registered for scheme: kms", err.Error())
}

func TestResolverNotFoundError_Error_EmptyScheme(t *testing.T) {
	err := &ResolverNotFoundError{Scheme: ""}
	assert.Equal(t, "secrets: no resolver registered for scheme: ", err.Error())
}

func TestResolutionError_Error(t *testing.T) {
	cause := &InvalidURIError{URI: "kms://bad", Message: "not found"}
	err := &ResolutionError{URI: "kms://bad", Cause: cause}
	assert.Equal(t, "secrets: failed to resolve kms://bad: secrets: invalid URI kms://bad: not found", err.Error())
}

func TestResolutionError_Unwrap(t *testing.T) {
	cause := &InvalidURIError{URI: "kms://bad", Message: "not found"}
	err := &ResolutionError{URI: "kms://bad", Cause: cause}

	unwrapped := err.Unwrap()
	require.NotNil(t, unwrapped)
	assert.Equal(t, cause, unwrapped)

	var target *InvalidURIError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "kms://bad", target.URI)
}

func TestProcessingError_Error(t *testing.T) {
	cause := &ResolverNotFoundError{Scheme: "vault"}
	err := &ProcessingError{Field: "Database.Password", Cause: cause}
	assert.Equal(t, "secrets: failed to process field Database.Password: secrets: no resolver registered for scheme: vault", err.Error())
}

func TestProcessingError_Unwrap(t *testing.T) {
	cause := &ResolverNotFoundError{Scheme: "vault"}
	err := &ProcessingError{Field: "Password", Cause: cause}

	unwrapped := err.Unwrap()
	require.NotNil(t, unwrapped)
	assert.Equal(t, cause, unwrapped)

	var target *ResolverNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "vault", target.Scheme)
}

func TestInvalidURIError_Error(t *testing.T) {
	err := &InvalidURIError{URI: "kms://invalid", Message: "missing key path"}
	assert.Equal(t, "secrets: invalid URI kms://invalid: missing key path", err.Error())
}

func TestInvalidURIError_Error_EmptyFields(t *testing.T) {
	err := &InvalidURIError{URI: "", Message: ""}
	assert.Equal(t, "secrets: invalid URI : ", err.Error())
}

func TestEnvVarNotSetError_Error(t *testing.T) {
	err := &EnvVarNotSetError{VarName: "SECRET_KEY"}
	assert.Equal(t, "secrets: environment variable not set: SECRET_KEY", err.Error())
}

func TestEnvVarNotSetError_Error_EmptyVarName(t *testing.T) {
	err := &EnvVarNotSetError{VarName: ""}
	assert.Equal(t, "secrets: environment variable not set: ", err.Error())
}

func TestEmptySecretError_Error(t *testing.T) {
	err := &EmptySecretError{}
	assert.Equal(t, "secrets: cannot seal an empty value into protected memory", err.Error())
}

func TestSealError_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("no protected pages available")
	err := &SealError{Cause: cause}
	assert.Contains(t, err.Error(), "no protected pages available")
	assert.Equal(t, cause, err.Unwrap())
	assert.ErrorIs(t, err, cause)
}

func TestUnavailableSecretError_Error(t *testing.T) {
	assert.Equal(t,
		"secrets: secret is unavailable: unset or destroyed",
		(&UnavailableSecretError{}).Error())

	cause := errors.New("enclave reaped")
	wrapped := &UnavailableSecretError{Cause: cause}
	assert.Contains(t, wrapped.Error(), "enclave reaped")
	assert.ErrorIs(t, wrapped, cause)
}
