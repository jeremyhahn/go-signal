package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAutoGenResolver_Scheme(t *testing.T) {
	r := NewAutoGenResolver(32)
	assert.Equal(t, "autogen", r.Scheme())
}

func TestAutoGenResolver_Resolve_AutoSentinel(t *testing.T) {
	r := NewAutoGenResolver(32)

	result, err := r.Resolve(context.Background(), "auto")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()

	plain := result.Plaintext(t.Context())
	assert.Len(t, plain, 64) // 32 bytes → 64 hex chars
	assert.NotEqual(t, "auto", plain)
}

func TestAutoGenResolver_Resolve_ChangemeSentinel(t *testing.T) {
	r := NewAutoGenResolver(16)

	result, err := r.Resolve(context.Background(), "changeme")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()

	assert.Len(t, result.Plaintext(t.Context()), 32) // 16 bytes → 32 hex chars
}

func TestAutoGenResolver_Resolve_PlaceholderSentinel(t *testing.T) {
	r := NewAutoGenResolver(32)

	result, err := r.Resolve(context.Background(), "placeholder")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()

	assert.Len(t, result.Plaintext(t.Context()), 64)
}

func TestAutoGenResolver_Resolve_NonSentinelPassthrough(t *testing.T) {
	r := NewAutoGenResolver(32)

	result, err := r.Resolve(context.Background(), "actual-password")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()

	assert.Equal(t, "actual-password", result.Plaintext(t.Context()))
}

func TestAutoGenResolver_Resolve_CachedOnSecondCall(t *testing.T) {
	r := NewAutoGenResolver(32)

	first, err := r.Resolve(context.Background(), "auto")
	require.NoError(t, err)
	defer first.Destroy()

	second, err := r.Resolve(context.Background(), "auto")
	require.NoError(t, err)
	defer second.Destroy()

	assert.Equal(t, first.Plaintext(t.Context()), second.Plaintext(t.Context()))
}

func TestAutoGenResolver_Resolve_DifferentSentinelsDifferentValues(t *testing.T) {
	r := NewAutoGenResolver(32)

	autoResult, err := r.Resolve(context.Background(), "auto")
	require.NoError(t, err)
	defer autoResult.Destroy()

	changemeResult, err := r.Resolve(context.Background(), "changeme")
	require.NoError(t, err)
	defer changemeResult.Destroy()

	assert.NotEqual(t, autoResult.Plaintext(t.Context()), changemeResult.Plaintext(t.Context()))
}

func TestAutoGenResolver_DefaultByteLength(t *testing.T) {
	r := NewAutoGenResolver(0)

	result, err := r.Resolve(context.Background(), "auto")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()

	assert.Len(t, result.Plaintext(t.Context()), 64) // default 32 bytes → 64 hex chars
}

func TestAutoGenResolver_Resolve_ReturnsSecureString(t *testing.T) {
	r := NewAutoGenResolver(32)

	result, err := r.Resolve(context.Background(), "auto")
	require.NoError(t, err)
	require.NotNil(t, result)
	defer result.Destroy()

	// String() must never expose the generated secret.
	assert.Equal(t, redacted, result.String())
	assert.NotEmpty(t, result.Plaintext(t.Context()))
}

func TestIsSentinel(t *testing.T) {
	assert.True(t, IsSentinel("auto"))
	assert.True(t, IsSentinel("changeme"))
	assert.True(t, IsSentinel("placeholder"))
	assert.False(t, IsSentinel("real-password"))
	assert.False(t, IsSentinel(""))
	assert.False(t, IsSentinel("Auto"))
}

// A sealing failure while generating a secret aborts the resolution instead
// of caching or returning an unset value.
func TestAutoGenResolver_SealFailure_Generate(t *testing.T) {
	r := NewAutoGenResolver(16)
	failSealing(t)

	s, err := r.Resolve(context.Background(), "auto")
	require.Error(t, err)
	assert.Nil(t, s)
	assert.Empty(t, r.cache, "a failed seal must not leave an entry behind")
}

// The same holds when serving an already-cached secret: the per-caller copy
// is sealed, and a failure there is reported rather than papered over.
func TestAutoGenResolver_SealFailure_CachedCopy(t *testing.T) {
	r := NewAutoGenResolver(16)
	first, err := r.Resolve(context.Background(), "auto")
	require.NoError(t, err)
	require.NotEmpty(t, first.Plaintext(t.Context()))

	// The per-caller copy is a Clone, which seals the copied buffer.
	failProtectedSeal(t, failSealing(t))
	s, err := r.Resolve(context.Background(), "auto")
	require.Error(t, err)
	assert.Nil(t, s)
}

// A non-sentinel value is passed through, so a sealing failure there is
// reported too.
func TestAutoGenResolver_SealFailure_Passthrough(t *testing.T) {
	r := NewAutoGenResolver(16)
	failSealing(t)

	s, err := r.Resolve(context.Background(), "plain-value")
	require.Error(t, err)
	assert.Nil(t, s)
}
