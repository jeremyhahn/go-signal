package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvResolver_Scheme(t *testing.T) {
	r := NewEnvResolver()
	assert.Equal(t, "env", r.Scheme())
}

func TestEnvResolver_Resolve_EnvVarSet(t *testing.T) {
	t.Setenv("TEST_SECRET_VALUE", "my-secret")
	r := NewEnvResolver()

	result, err := r.Resolve(context.Background(), "${TEST_SECRET_VALUE}")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()
	assert.Equal(t, "my-secret", result.Plaintext(t.Context()))
}

func TestEnvResolver_Resolve_EnvVarNotSet(t *testing.T) {
	r := NewEnvResolver()

	_, err := r.Resolve(context.Background(), "${NONEXISTENT_VAR_12345}")
	require.Error(t, err)

	var envErr *EnvVarNotSetError
	require.ErrorAs(t, err, &envErr)
	assert.Equal(t, "NONEXISTENT_VAR_12345", envErr.VarName)
}

func TestEnvResolver_Resolve_PlainValuePassthrough(t *testing.T) {
	r := NewEnvResolver()

	result, err := r.Resolve(context.Background(), "plain-value")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()
	assert.Equal(t, "plain-value", result.Plaintext(t.Context()))
}

func TestEnvResolver_Resolve_EmptyValue(t *testing.T) {
	r := NewEnvResolver()

	result, err := r.Resolve(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()
	assert.Equal(t, "", result.Plaintext(t.Context()))
}

func TestEnvResolver_Resolve_EmptyEnvVarValue(t *testing.T) {
	t.Setenv("TEST_EMPTY_VAR", "")
	r := NewEnvResolver()

	result, err := r.Resolve(context.Background(), "${TEST_EMPTY_VAR}")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()
	assert.Equal(t, "", result.Plaintext(t.Context()))
}

func TestEnvResolver_Resolve_ReturnsSecureString(t *testing.T) {
	t.Setenv("TEST_SECURE_VAR", "secure-secret")
	r := NewEnvResolver()

	result, err := r.Resolve(context.Background(), "${TEST_SECURE_VAR}")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()

	// String() must never expose the plaintext value.
	assert.Equal(t, redacted, result.String())
	assert.Equal(t, "secure-secret", result.Plaintext(t.Context()))
}

func TestIsEnvVar(t *testing.T) {
	assert.True(t, IsEnvVar("${FOO}"))
	assert.True(t, IsEnvVar("${MY_SECRET_123}"))
	assert.True(t, IsEnvVar("  ${TRIMMED}  "))
	assert.False(t, IsEnvVar("$FOO"))
	assert.False(t, IsEnvVar("FOO"))
	assert.False(t, IsEnvVar("${}"))
	assert.False(t, IsEnvVar(""))
	assert.False(t, IsEnvVar("${"))
	assert.False(t, IsEnvVar("}"))
}

func TestParseEnvVar(t *testing.T) {
	tests := []struct {
		input   string
		varName string
		ok      bool
	}{
		{"${FOO}", "FOO", true},
		{"${MY_SECRET}", "MY_SECRET", true},
		{"  ${TRIMMED}  ", "TRIMMED", true},
		{"$FOO", "", false},
		{"plain", "", false},
		{"${}", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			varName, ok := parseEnvVar(tt.input)
			assert.Equal(t, tt.ok, ok)
			if ok {
				assert.Equal(t, tt.varName, varName)
			}
		})
	}
}
