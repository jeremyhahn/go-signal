//go:build desktop

package desktop

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type startupCtxKey struct{}

// TestApp_IsRegisteredBeforeStartup: Wails calls the frontend-bound methods
// before Startup has run, so the application context was still nil and an
// explicit DAOStore panicked in context.WithTimeout.
func TestApp_IsRegisteredBeforeStartup(t *testing.T) {
	app := newTestAppWithDAOStore(t, "http://127.0.0.1:19997")

	require.NotPanics(t, func() {
		registered, err := app.IsRegistered()
		require.NoError(t, err)
		assert.False(t, registered)
	})
}

// TestApp_NewAppSeedsTheApplicationContext: the context handed to NewApp is the
// one in force until Wails supplies its own.
func TestApp_NewAppSeedsTheApplicationContext(t *testing.T) {
	ctx := context.WithValue(t.Context(), startupCtxKey{}, "new-app")
	app, err := NewApp(ctx, newTestAppConfig())
	require.NoError(t, err)

	require.NotNil(t, app.ctx)
	assert.Equal(t, "new-app", app.ctx.Value(startupCtxKey{}))
}

// TestApp_StartupReplacesTheApplicationContext: Startup's context supersedes the
// seeded one.
func TestApp_StartupReplacesTheApplicationContext(t *testing.T) {
	app, err := NewApp(t.Context(), newTestAppConfig())
	require.NoError(t, err)

	app.Startup(context.WithValue(t.Context(), startupCtxKey{}, "wails"))

	assert.Equal(t, "wails", app.ctx.Value(startupCtxKey{}))
}
