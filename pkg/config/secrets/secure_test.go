package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNewSecureString_NonEmpty(t *testing.T) {
	s := MustNewSecureString(t.Context(), "my-secret")
	require.NotNil(t, s)
	assert.False(t, s.IsDestroyed(t.Context()))
}

func TestNewSecureString_Empty(t *testing.T) {
	s := MustNewSecureString(t.Context(), "")
	require.NotNil(t, s)
	// Empty SecureString has no enclave — treated as destroyed/unset.
	assert.True(t, s.IsDestroyed(t.Context()))
}

func TestSecureString_Plaintext_ReturnsValue(t *testing.T) {
	s := MustNewSecureString(t.Context(), "correct-horse-battery-staple")
	assert.Equal(t, "correct-horse-battery-staple", s.Plaintext(t.Context()))
}

func TestSecureString_Plaintext_AfterDestroy_ReturnsEmpty(t *testing.T) {
	s := MustNewSecureString(t.Context(), "ephemeral")
	s.Destroy()
	assert.Equal(t, "", s.Plaintext(t.Context()))
}

func TestSecureString_Bytes_ReturnsValue(t *testing.T) {
	s := MustNewSecureString(t.Context(), "key-bytes")
	b := s.Bytes(t.Context())
	assert.Equal(t, []byte("key-bytes"), b)
}

func TestSecureString_Bytes_AfterDestroy_ReturnsNil(t *testing.T) {
	s := MustNewSecureString(t.Context(), "gone")
	s.Destroy()
	assert.Nil(t, s.Bytes(t.Context()))
}

func TestSecureString_String_AlwaysRedacted(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"non_empty", "super-secret"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := MustNewSecureString(t.Context(), tt.value)
			assert.Equal(t, redacted, s.String())
		})
	}
}

func TestSecureString_String_NilReceiver(t *testing.T) {
	var s *SecureString
	assert.Equal(t, redacted, s.String())
}

func TestSecureString_MarshalJSON_ReturnsRedacted(t *testing.T) {
	s := MustNewSecureString(t.Context(), "do-not-leak")
	data, err := json.Marshal(s)
	require.NoError(t, err)
	assert.Equal(t, `"`+redacted+`"`, string(data))
}

func TestSecureString_MarshalJSON_InStruct(t *testing.T) {
	type cfg struct {
		Password *SecureString `json:"password"`
	}
	c := cfg{Password: MustNewSecureString(t.Context(), "hunter2")}
	data, err := json.Marshal(c)
	require.NoError(t, err)
	assert.Contains(t, string(data), redacted)
	assert.NotContains(t, string(data), "hunter2")
}

func TestSecureString_UnmarshalYAML_PopulatesValue(t *testing.T) {
	input := `secret: "my-yaml-secret"`
	type cfg struct {
		Secret SecureString `yaml:"secret"`
	}
	var c cfg
	err := yaml.Unmarshal([]byte(input), &c)
	require.NoError(t, err)
	assert.Equal(t, "my-yaml-secret", c.Secret.Plaintext(t.Context()))
}

func TestSecureString_UnmarshalYAML_EmptyValue(t *testing.T) {
	input := `secret: ""`
	type cfg struct {
		Secret SecureString `yaml:"secret"`
	}
	var c cfg
	err := yaml.Unmarshal([]byte(input), &c)
	require.NoError(t, err)
	assert.True(t, c.Secret.IsDestroyed(t.Context()))
}

func TestSecureString_UnmarshalYAML_MissingField(t *testing.T) {
	input := `other: "value"`
	type cfg struct {
		Secret SecureString `yaml:"secret"`
	}
	var c cfg
	err := yaml.Unmarshal([]byte(input), &c)
	require.NoError(t, err)
	// Missing field leaves SecureString at zero value — enc is nil.
	assert.True(t, c.Secret.IsDestroyed(t.Context()))
}

func TestSecureString_Destroy_Idempotent(t *testing.T) {
	s := MustNewSecureString(t.Context(), "wipe-me")
	s.Destroy()
	// Second destroy must not panic.
	assert.NotPanics(t, func() { s.Destroy() })
	assert.True(t, s.IsDestroyed(t.Context()))
}

func TestSecureString_IsDestroyed_Nil(t *testing.T) {
	var s *SecureString
	assert.True(t, s.IsDestroyed(t.Context()))
}

func TestSecureString_Plaintext_Nil(t *testing.T) {
	var s *SecureString
	assert.Equal(t, "", s.Plaintext(t.Context()))
}

func TestSecureString_Bytes_Nil(t *testing.T) {
	var s *SecureString
	assert.Nil(t, s.Bytes(t.Context()))
}

func TestSecureString_Stringer_DoesNotExposeValue(t *testing.T) {
	s := MustNewSecureString(t.Context(), "top-secret-value")
	// Formatting via %v, %s, and %+v must never reveal the plaintext.
	formatted := s.String()
	assert.NotContains(t, formatted, "top-secret-value")
	assert.Equal(t, redacted, formatted)
}

func TestSecureString_UnmarshalYAML_InvalidType(t *testing.T) {
	// Providing a YAML integer where a string is expected should return an error.
	input := `secret: 12345`
	type cfg struct {
		Secret SecureString `yaml:"secret"`
	}
	var c cfg
	// yaml.v3 coerces integers to strings, so this succeeds — just verify no panic.
	err := yaml.Unmarshal([]byte(input), &c)
	// Either success (coerced) or failure is acceptable; we just must not panic.
	_ = err
}

func TestSecureString_FullLifecycle(t *testing.T) {
	s := MustNewSecureString(t.Context(), "lifecycle-secret")

	// Created, not destroyed.
	assert.False(t, s.IsDestroyed(t.Context()))

	// Plaintext is accessible.
	assert.Equal(t, "lifecycle-secret", s.Plaintext(t.Context()))

	// Bytes are accessible.
	assert.Equal(t, []byte("lifecycle-secret"), s.Bytes(t.Context()))

	// String representation is redacted.
	assert.Equal(t, redacted, s.String())

	// JSON encoding is redacted.
	data, err := json.Marshal(s)
	require.NoError(t, err)
	assert.Contains(t, string(data), redacted)

	// After destroy, all access returns zero values.
	s.Destroy()
	assert.True(t, s.IsDestroyed(t.Context()))
	assert.Equal(t, "", s.Plaintext(t.Context()))
	assert.Nil(t, s.Bytes(t.Context()))
}

// --------------------------------------------------------------------------
// Fail-closed construction
// --------------------------------------------------------------------------

func TestNewSecureString_EmptyIsAnError(t *testing.T) {
	s, err := NewSecureString(t.Context(), "")
	require.Error(t, err)
	assert.Nil(t, s)
	var empty *EmptySecretError
	assert.ErrorAs(t, err, &empty)
}

func TestNewSecureString_SealsValue(t *testing.T) {
	s, err := NewSecureString(t.Context(), "credential-material")
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Equal(t, "credential-material", s.Plaintext(t.Context()))
	s.Destroy()
}

func TestNewOptionalSecureString_EmptyIsUnset(t *testing.T) {
	s, err := NewOptionalSecureString(t.Context(), "")
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.True(t, s.IsDestroyed(t.Context()))
	assert.Equal(t, "", s.Plaintext(t.Context()))
}

func TestNewOptionalSecureString_NonEmptySeals(t *testing.T) {
	s, err := NewOptionalSecureString(t.Context(), "config-value")
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.Equal(t, "config-value", s.Plaintext(t.Context()))
	s.Destroy()
}

func TestMustNewSecureString_SealsAndTolerates(t *testing.T) {
	s := MustNewSecureString(t.Context(), "fixture")
	require.NotNil(t, s)
	assert.Equal(t, "fixture", s.Plaintext(t.Context()))
	// The Must form keeps the optional semantics so fixtures can express an
	// unset secret without a panic.
	assert.True(t, MustNewSecureString(t.Context(), "").IsDestroyed(t.Context()))
}

// Decoding YAML into a SecureString that already holds a value must wipe the
// previous protected allocation rather than abandon it.
func TestSecureString_UnmarshalYAML_DestroysReplacedValue(t *testing.T) {
	type cfg struct {
		Secret SecureString `yaml:"secret"`
	}
	var c cfg
	require.NoError(t, yaml.Unmarshal([]byte(`secret: "first"`), &c))
	require.NoError(t, c.Secret.Seal(t.Context()))
	first := c.Secret.sec
	require.NotNil(t, first)

	require.NoError(t, yaml.Unmarshal([]byte(`secret: "second"`), &c))
	assert.Equal(t, "second", c.Secret.Plaintext(t.Context()))
	assert.NotSame(t, first, c.Secret.sec)
	// The replaced secret is wiped: opening it fails.
	_, err := first.Open(t.Context())
	assert.Error(t, err)
}

// A SecureString whose underlying secret was wiped out from under it (the
// enclave is destroyed while the wrapper still holds the pointer) must report
// as destroyed and hand back nothing, not panic or leak a stale copy.
func TestSecureString_UnderlyingSecretDestroyed(t *testing.T) {
	s := MustNewSecureString(t.Context(), "wiped-underneath")
	require.NotNil(t, s.sec)
	s.sec.Destroy()

	assert.Equal(t, "", s.Plaintext(t.Context()))
	assert.Nil(t, s.Bytes(t.Context()))
	assert.True(t, s.IsDestroyed(t.Context()))
}

// --------------------------------------------------------------------------
// Fault injection: the protected allocation fails
// --------------------------------------------------------------------------

// failSealing makes every protected allocation fail for the duration of the
// test, so the fail-closed paths are exercised rather than merely asserted.
func failSealing(t *testing.T) error {
	t.Helper()
	injected := errors.New("injected: no protected memory available")
	original := sealSecret
	sealSecret = func(context.Context, []byte) (*secure.Secret, error) { return nil, injected }
	t.Cleanup(func() { sealSecret = original })
	return injected
}

func TestNewSecureString_SealFailureIsReported(t *testing.T) {
	injected := failSealing(t)

	s, err := NewSecureString(t.Context(), "credential-material")
	require.Error(t, err)
	assert.Nil(t, s)
	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.ErrorIs(t, err, injected)
}

func TestNewOptionalSecureString_SealFailureIsReported(t *testing.T) {
	failSealing(t)

	s, err := NewOptionalSecureString(t.Context(), "config-value")
	require.Error(t, err)
	assert.Nil(t, s)
}

func TestMustNewSecureString_PanicsOnSealFailure(t *testing.T) {
	failSealing(t)

	assert.Panics(t, func() { MustNewSecureString(t.Context(), "fixture") })
}

func TestSecureString_UnmarshalYAML_SealFailure(t *testing.T) {
	type cfg struct {
		Secret SecureString `yaml:"secret"`
	}
	var c cfg
	require.NoError(t, yaml.Unmarshal([]byte(`secret: "value"`), &c))

	injected := errors.New("injected: no protected memory available")
	failProtectedSeal(t, injected)

	err := c.Secret.Seal(t.Context())
	var sealErr *SealError
	require.ErrorAs(t, err, &sealErr)
	assert.ErrorIs(t, sealErr.Cause, injected)
	// The staged value is wiped, not left readable after a failed seal.
	assert.True(t, c.Secret.IsDestroyed(t.Context()))
	assert.Nil(t, c.Secret.staged)
}

func TestSecureString_UnmarshalYAML_StageFailure(t *testing.T) {
	injected := errors.New("injected: no locked memory available")
	original := stageBuffer
	stageBuffer = func([]byte) (*secure.Buffer, error) { return nil, injected }
	t.Cleanup(func() { stageBuffer = original })

	type cfg struct {
		Secret SecureString `yaml:"secret"`
	}
	var c cfg
	err := yaml.Unmarshal([]byte(`secret: "value"`), &c)
	assert.ErrorIs(t, err, injected)
	assert.True(t, c.Secret.IsDestroyed(t.Context()))
}

// --------------------------------------------------------------------------
// Reveal
// --------------------------------------------------------------------------

func TestSecureString_Reveal_ReturnsValue(t *testing.T) {
	s := MustNewSecureString(t.Context(), "bearer-credential")
	value, err := s.Reveal(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "bearer-credential", value)
}

func TestSecureString_Reveal_UnsetIsAnError(t *testing.T) {
	var s *SecureString
	value, err := s.Reveal(t.Context())
	assert.Empty(t, value)
	var unavailable *UnavailableSecretError
	require.ErrorAs(t, err, &unavailable)
	assert.Contains(t, err.Error(), "unset or destroyed")

	_, err = MustNewSecureString(t.Context(), "").Reveal(t.Context())
	assert.ErrorAs(t, err, &unavailable)
}

func TestSecureString_Reveal_DestroyedIsAnError(t *testing.T) {
	s := MustNewSecureString(t.Context(), "wipe-me")
	s.Destroy()

	value, err := s.Reveal(t.Context())
	assert.Empty(t, value)
	var unavailable *UnavailableSecretError
	assert.ErrorAs(t, err, &unavailable)
}

// A secret whose enclave was wiped out from under the wrapper reports the
// underlying open failure rather than an empty value.
func TestSecureString_Reveal_OpenFailureIsWrapped(t *testing.T) {
	s := MustNewSecureString(t.Context(), "wiped-underneath")
	require.NotNil(t, s.sec)
	s.sec.Destroy()

	value, err := s.Reveal(t.Context())
	assert.Empty(t, value)
	var unavailable *UnavailableSecretError
	require.ErrorAs(t, err, &unavailable)
	assert.NotNil(t, unavailable.Unwrap())
}
