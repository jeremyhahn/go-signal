package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockResolver is a test double that returns a fixed plaintext value.
type mockResolver struct {
	scheme   string
	resolved string
	err      error
}

func (m *mockResolver) Scheme() string { return m.scheme }
func (m *mockResolver) Resolve(_ context.Context, _ string) (*SecureString, error) {
	if m.err != nil {
		return nil, m.err
	}
	return NewSecureString(m.resolved), nil
}

func TestResolverRegistry_Resolve_RegisteredScheme(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(&mockResolver{scheme: "kms", resolved: "secret-value"})

	result, err := registry.Resolve(context.Background(), "kms://path/to/secret")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()
	assert.Equal(t, "secret-value", result.Plaintext())
}

func TestResolverRegistry_Resolve_UnregisteredScheme(t *testing.T) {
	registry := NewResolverRegistry()

	_, err := registry.Resolve(context.Background(), "kms://path/to/secret")
	require.Error(t, err)

	var notFound *ResolverNotFoundError
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "kms", notFound.Scheme)
}

func TestResolverRegistry_Resolve_PlainValue(t *testing.T) {
	registry := NewResolverRegistry()

	result, err := registry.Resolve(context.Background(), "just-a-plain-value")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()
	assert.Equal(t, "just-a-plain-value", result.Plaintext())
}

func TestResolverRegistry_Resolve_EmptyValue(t *testing.T) {
	registry := NewResolverRegistry()

	result, err := registry.Resolve(context.Background(), "")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()
	assert.Equal(t, "", result.Plaintext())
}

func TestResolverRegistry_HasResolver(t *testing.T) {
	registry := NewResolverRegistry()
	assert.False(t, registry.HasResolver("kms"))

	registry.Register(&mockResolver{scheme: "kms"})
	assert.True(t, registry.HasResolver("kms"))
}

func TestResolverRegistry_Register_OverwritesPrevious(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(&mockResolver{scheme: "kms", resolved: "first"})
	registry.Register(&mockResolver{scheme: "kms", resolved: "second"})

	result, err := registry.Resolve(context.Background(), "kms://test")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()
	assert.Equal(t, "second", result.Plaintext())
}

func TestResolverRegistry_Resolve_ResolverError(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(&mockResolver{
		scheme: "kms",
		err:    &InvalidURIError{URI: "kms://bad", Message: "invalid path"},
	})

	_, err := registry.Resolve(context.Background(), "kms://bad")
	require.Error(t, err)

	var resErr *ResolutionError
	require.ErrorAs(t, err, &resErr)
	assert.Equal(t, "kms://bad", resErr.URI)
}

func TestResolverRegistry_Resolve_ReturnsSecureString(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(&mockResolver{scheme: "kms", resolved: "sensitive-data"})

	result, err := registry.Resolve(context.Background(), "kms://path")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()

	// String() must never expose the plaintext.
	assert.Equal(t, redacted, result.String())
	assert.Equal(t, "sensitive-data", result.Plaintext())
}

func TestParseScheme(t *testing.T) {
	tests := []struct {
		input  string
		scheme string
		rest   string
		ok     bool
	}{
		{"kms://path/to/secret", "kms", "path/to/secret", true},
		{"remote-kms://host:8080/path", "remote-kms", "host:8080/path", true},
		{"env://VAR_NAME", "env", "VAR_NAME", true},
		{"plain-value", "", "", false},
		{"://no-scheme", "", "", false},
		{"", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			scheme, rest, ok := parseScheme(tt.input)
			assert.Equal(t, tt.ok, ok)
			if ok {
				assert.Equal(t, tt.scheme, scheme)
				assert.Equal(t, tt.rest, rest)
			}
		})
	}
}
