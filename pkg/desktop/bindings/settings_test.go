//go:build desktop

package bindings

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSettingsBindings verifies construction.
func TestNewSettingsBindings(t *testing.T) {
	t.Run("WithClientAndFactory", func(t *testing.T) {
		b := NewSettingsBindings(newBindClient(t), newTestBindFactory(t))
		require.NotNil(t, b)
	})
}

// TestSettingsBindings_GetSettings tests loading settings with defaults.
func TestSettingsBindings_GetSettings(t *testing.T) {
	t.Run("DefaultsWhenEmpty", func(t *testing.T) {
		b := NewSettingsBindings(newBindClient(t), newTestBindFactory(t))
		settings, err := b.GetSettings()
		require.NoError(t, err)
		require.NotNil(t, settings)
		// Defaults must be applied.
		assert.Equal(t, "system", settings.Theme)
		assert.Equal(t, "en", settings.Locale)
		assert.True(t, settings.NotificationsEnabled)
		assert.True(t, settings.ReadReceipts)
		assert.True(t, settings.TypingIndicators)
		assert.True(t, settings.LinkPreviews)
	})
	t.Run("ReturnsStoredTheme", func(t *testing.T) {
		b := NewSettingsBindings(newBindClient(t), newTestBindFactory(t))
		require.NoError(t, b.UpdateSettings("theme", "dark"))

		settings, err := b.GetSettings()
		require.NoError(t, err)
		assert.Equal(t, "dark", settings.Theme)
	})
}

// TestSettingsBindings_SetPin tests setting the registration lock PIN.
func TestSettingsBindings_SetPin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || r.URL.Path != "/v1/accounts/registration_lock" {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		b := NewSettingsBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		require.NoError(t, b.SetPin("123456"))
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		b := NewSettingsBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		require.Error(t, b.SetPin("000000"))
	})
}

// TestSettingsBindings_RemovePin tests removing the registration lock PIN.
func TestSettingsBindings_RemovePin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete || r.URL.Path != "/v1/accounts/registration_lock" {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		b := NewSettingsBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		require.NoError(t, b.RemovePin())
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusUnauthorized)
		}))
		defer srv.Close()

		b := NewSettingsBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		require.Error(t, b.RemovePin())
	})
}

// TestSettingsBindings_UpdateSettings tests creating and updating settings.
func TestSettingsBindings_UpdateSettings(t *testing.T) {
	t.Run("CreatesNewSetting", func(t *testing.T) {
		b := NewSettingsBindings(newBindClient(t), newTestBindFactory(t))
		err := b.UpdateSettings("locale", "fr")
		require.NoError(t, err)

		settings, err := b.GetSettings()
		require.NoError(t, err)
		assert.Equal(t, "fr", settings.Locale)
	})
	t.Run("UpdatesExistingSetting", func(t *testing.T) {
		b := NewSettingsBindings(newBindClient(t), newTestBindFactory(t))
		require.NoError(t, b.UpdateSettings("theme", "light"))
		require.NoError(t, b.UpdateSettings("theme", "dark"))

		settings, err := b.GetSettings()
		require.NoError(t, err)
		assert.Equal(t, "dark", settings.Theme)
	})
	t.Run("MultipleSettings", func(t *testing.T) {
		b := NewSettingsBindings(newBindClient(t), newTestBindFactory(t))
		require.NoError(t, b.UpdateSettings("theme", "dark"))
		require.NoError(t, b.UpdateSettings("locale", "de"))

		settings, err := b.GetSettings()
		require.NoError(t, err)
		assert.Equal(t, "dark", settings.Theme)
		assert.Equal(t, "de", settings.Locale)
	})
}
