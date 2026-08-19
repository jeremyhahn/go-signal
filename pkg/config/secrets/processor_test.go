package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testConfig struct {
	Host     string
	Port     int
	Password string
	Nested   testNestedConfig
	Pointer  *testNestedConfig
}

type testNestedConfig struct {
	Secret string
	Label  string
}

// testSecureConfig mirrors testConfig but uses *SecureString for secret fields.
type testSecureConfig struct {
	Host     string
	Password *SecureString
	Nested   testSecureNestedConfig
}

type testSecureNestedConfig struct {
	Secret *SecureString
	Label  string
}

func TestConfigProcessor_Process_ResolvesURIs(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(&mockResolver{scheme: "kms", resolved: "resolved-secret"})

	cfg := &testConfig{
		Host:     "localhost",
		Password: "kms://signal/smtp/password",
		Nested: testNestedConfig{
			Secret: "kms://signal/nested/secret",
			Label:  "plain-label",
		},
	}

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)

	assert.Equal(t, "localhost", cfg.Host)
	assert.Equal(t, "resolved-secret", cfg.Password)
	assert.Equal(t, "resolved-secret", cfg.Nested.Secret)
	assert.Equal(t, "plain-label", cfg.Nested.Label)
}

func TestConfigProcessor_Process_PointerField(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(&mockResolver{scheme: "kms", resolved: "ptr-secret"})

	cfg := &testConfig{
		Pointer: &testNestedConfig{
			Secret: "kms://signal/ptr/secret",
			Label:  "label",
		},
	}

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)

	assert.Equal(t, "ptr-secret", cfg.Pointer.Secret)
	assert.Equal(t, "label", cfg.Pointer.Label)
}

func TestConfigProcessor_Process_NilPointerField(t *testing.T) {
	registry := NewResolverRegistry()

	cfg := &testConfig{
		Host:    "localhost",
		Pointer: nil,
	}

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)
	assert.Nil(t, cfg.Pointer)
}

func TestConfigProcessor_Process_NonPointerError(t *testing.T) {
	registry := NewResolverRegistry()
	processor := NewConfigProcessor(registry)

	cfg := testConfig{Host: "localhost"}
	err := processor.Process(context.Background(), cfg)
	require.Error(t, err)

	var procErr *ProcessingError
	require.ErrorAs(t, err, &procErr)
}

func TestConfigProcessor_Process_EmptyStringsSkipped(t *testing.T) {
	registry := NewResolverRegistry()

	cfg := &testConfig{
		Host:     "",
		Password: "",
	}

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)

	assert.Equal(t, "", cfg.Host)
	assert.Equal(t, "", cfg.Password)
}

func TestConfigProcessor_Process_PlainValuesUnchanged(t *testing.T) {
	registry := NewResolverRegistry()

	cfg := &testConfig{
		Host:     "localhost",
		Password: "plain-password",
	}

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)

	assert.Equal(t, "localhost", cfg.Host)
	assert.Equal(t, "plain-password", cfg.Password)
}

func TestConfigProcessor_Process_ResolutionError(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(&mockResolver{
		scheme: "kms",
		err:    &InvalidURIError{URI: "kms://bad", Message: "not found"},
	})

	cfg := &testConfig{
		Password: "kms://bad",
	}

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.Error(t, err)

	var procErr *ProcessingError
	require.ErrorAs(t, err, &procErr)
	assert.Equal(t, "Password", procErr.Field)
}

// testConfigWithUnexported contains unexported fields that the processor must skip.
type testConfigWithUnexported struct {
	Public  string
	private string //nolint:unused
}

func TestConfigProcessor_Process_UnexportedFieldsSkipped(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(&mockResolver{scheme: "kms", resolved: "resolved"})

	cfg := &testConfigWithUnexported{
		Public: "kms://signal/public",
	}

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)

	assert.Equal(t, "resolved", cfg.Public)
}

func TestConfigProcessor_Process_PointerToNonStruct(t *testing.T) {
	registry := NewResolverRegistry()
	processor := NewConfigProcessor(registry)

	err := processor.Process(context.Background(), "not-a-pointer")
	require.Error(t, err)

	var procErr *ProcessingError
	require.ErrorAs(t, err, &procErr)
	assert.Equal(t, "<root>", procErr.Field)
}

// --- SecureString field tests ---

func TestConfigProcessor_Process_SecureStringField_ResolvedURI(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(&mockResolver{scheme: "kms", resolved: "kms-resolved-secret"})

	cfg := &testSecureConfig{
		Password: MustNewSecureString("kms://signal/password"),
	}
	defer cfg.Password.Destroy()

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)

	require.NotNil(t, cfg.Password)
	assert.Equal(t, "kms-resolved-secret", cfg.Password.Plaintext())
}

func TestConfigProcessor_Process_SecureStringField_PlainValue_Unchanged(t *testing.T) {
	registry := NewResolverRegistry()

	cfg := &testSecureConfig{
		Password: MustNewSecureString("plain-secret"),
	}
	defer cfg.Password.Destroy()

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)

	assert.Equal(t, "plain-secret", cfg.Password.Plaintext())
}

func TestConfigProcessor_Process_SecureStringField_NilField_Skipped(t *testing.T) {
	registry := NewResolverRegistry()

	cfg := &testSecureConfig{
		Password: nil,
	}

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)
	// Nil SecureString is skipped without error.
	assert.Nil(t, cfg.Password)
}

func TestConfigProcessor_Process_SecureStringField_ResolutionError(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(&mockResolver{
		scheme: "kms",
		err:    &InvalidURIError{URI: "kms://fail", Message: "not found"},
	})

	cfg := &testSecureConfig{
		Password: MustNewSecureString("kms://fail"),
	}
	if cfg.Password != nil {
		defer cfg.Password.Destroy()
	}

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.Error(t, err)

	var procErr *ProcessingError
	require.ErrorAs(t, err, &procErr)
	assert.Equal(t, "Password", procErr.Field)
}

func TestConfigProcessor_Process_SecureStringField_EmptyPlaintext_Skipped(t *testing.T) {
	registry := NewResolverRegistry()

	// A *SecureString created from empty string should be skipped by processor.
	cfg := &testSecureConfig{
		Password: MustNewSecureString(""),
	}
	defer cfg.Password.Destroy()

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)
}

func TestConfigProcessor_Process_SecureStringField_NestedStruct(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(&mockResolver{scheme: "kms", resolved: "nested-kms-secret"})

	cfg := &testSecureConfig{
		Nested: testSecureNestedConfig{
			Secret: MustNewSecureString("kms://signal/nested"),
			Label:  "label",
		},
	}
	defer cfg.Nested.Secret.Destroy()

	processor := NewConfigProcessor(registry)
	err := processor.Process(context.Background(), cfg)
	require.NoError(t, err)

	assert.Equal(t, "nested-kms-secret", cfg.Nested.Secret.Plaintext())
	assert.Equal(t, "label", cfg.Nested.Label)
}

// Unexported fields cannot be set through reflection; the processor skips
// them rather than panicking.
func TestConfigProcessor_SkipsUnsettableFields(t *testing.T) {
	type inner struct {
		//nolint:unused // present to exercise the unexported-field skip path
		secret *SecureString
		//nolint:unused // present to exercise the unexported-field skip path
		token string
	}
	type outer struct {
		Inner inner
	}

	p := NewConfigProcessor(NewResolverRegistry())
	cfg := &outer{Inner: inner{secret: MustNewSecureString("unreachable"), token: "unreachable"}}
	require.NoError(t, p.Process(context.Background(), cfg))
}
