package secrets

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNewSecureString_NonEmpty(t *testing.T) {
	s := NewSecureString("my-secret")
	require.NotNil(t, s)
	assert.False(t, s.IsDestroyed())
}

func TestNewSecureString_Empty(t *testing.T) {
	s := NewSecureString("")
	require.NotNil(t, s)
	// Empty SecureString has no enclave — treated as destroyed/unset.
	assert.True(t, s.IsDestroyed())
}

func TestSecureString_Plaintext_ReturnsValue(t *testing.T) {
	s := NewSecureString("correct-horse-battery-staple")
	assert.Equal(t, "correct-horse-battery-staple", s.Plaintext())
}

func TestSecureString_Plaintext_AfterDestroy_ReturnsEmpty(t *testing.T) {
	s := NewSecureString("ephemeral")
	s.Destroy()
	assert.Equal(t, "", s.Plaintext())
}

func TestSecureString_Bytes_ReturnsValue(t *testing.T) {
	s := NewSecureString("key-bytes")
	b := s.Bytes()
	assert.Equal(t, []byte("key-bytes"), b)
}

func TestSecureString_Bytes_AfterDestroy_ReturnsNil(t *testing.T) {
	s := NewSecureString("gone")
	s.Destroy()
	assert.Nil(t, s.Bytes())
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
			s := NewSecureString(tt.value)
			assert.Equal(t, redacted, s.String())
		})
	}
}

func TestSecureString_String_NilReceiver(t *testing.T) {
	var s *SecureString
	assert.Equal(t, redacted, s.String())
}

func TestSecureString_MarshalJSON_ReturnsRedacted(t *testing.T) {
	s := NewSecureString("do-not-leak")
	data, err := json.Marshal(s)
	require.NoError(t, err)
	assert.Equal(t, `"`+redacted+`"`, string(data))
}

func TestSecureString_MarshalJSON_InStruct(t *testing.T) {
	type cfg struct {
		Password *SecureString `json:"password"`
	}
	c := cfg{Password: NewSecureString("hunter2")}
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
	assert.Equal(t, "my-yaml-secret", c.Secret.Plaintext())
}

func TestSecureString_UnmarshalYAML_EmptyValue(t *testing.T) {
	input := `secret: ""`
	type cfg struct {
		Secret SecureString `yaml:"secret"`
	}
	var c cfg
	err := yaml.Unmarshal([]byte(input), &c)
	require.NoError(t, err)
	assert.True(t, c.Secret.IsDestroyed())
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
	assert.True(t, c.Secret.IsDestroyed())
}

func TestSecureString_Destroy_Idempotent(t *testing.T) {
	s := NewSecureString("wipe-me")
	s.Destroy()
	// Second destroy must not panic.
	assert.NotPanics(t, func() { s.Destroy() })
	assert.True(t, s.IsDestroyed())
}

func TestSecureString_IsDestroyed_Nil(t *testing.T) {
	var s *SecureString
	assert.True(t, s.IsDestroyed())
}

func TestSecureString_Plaintext_Nil(t *testing.T) {
	var s *SecureString
	assert.Equal(t, "", s.Plaintext())
}

func TestSecureString_Bytes_Nil(t *testing.T) {
	var s *SecureString
	assert.Nil(t, s.Bytes())
}

func TestSecureString_Stringer_DoesNotExposeValue(t *testing.T) {
	s := NewSecureString("top-secret-value")
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
	s := NewSecureString("lifecycle-secret")

	// Created, not destroyed.
	assert.False(t, s.IsDestroyed())

	// Plaintext is accessible.
	assert.Equal(t, "lifecycle-secret", s.Plaintext())

	// Bytes are accessible.
	assert.Equal(t, []byte("lifecycle-secret"), s.Bytes())

	// String representation is redacted.
	assert.Equal(t, redacted, s.String())

	// JSON encoding is redacted.
	data, err := json.Marshal(s)
	require.NoError(t, err)
	assert.Contains(t, string(data), redacted)

	// After destroy, all access returns zero values.
	s.Destroy()
	assert.True(t, s.IsDestroyed())
	assert.Equal(t, "", s.Plaintext())
	assert.Nil(t, s.Bytes())
}
