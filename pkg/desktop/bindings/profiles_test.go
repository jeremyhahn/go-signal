//go:build desktop

package bindings

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// TestNewProfileBindings verifies construction.
func TestNewProfileBindings(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		b := NewProfileBindings(newBindClient(t))
		require.NotNil(t, b)
	})
	t.Run("RetainsClient", func(t *testing.T) {
		c := newBindClient(t)
		b := NewProfileBindings(c)
		require.NotNil(t, b.client)
	})
}

// TestProfileBindings_GetProfile tests fetching a user profile.
func TestProfileBindings_GetProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/v1/profile/user-uuid-1" {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signal.Profile{
				GivenName:  "Alice",
				FamilyName: "Smith",
			})
		}))
		defer srv.Close()

		b := NewProfileBindings(newBindClientURL(t, srv.URL))
		profile, err := b.GetProfile("user-uuid-1")
		require.NoError(t, err)
		require.NotNil(t, profile)
		assert.Equal(t, "Alice", profile.GivenName)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer srv.Close()

		b := NewProfileBindings(newBindClientURL(t, srv.URL))
		_, err := b.GetProfile("ghost-uuid")
		require.Error(t, err)
	})
}

// TestProfileBindings_UpdateProfile tests updating the authenticated user's profile.
func TestProfileBindings_UpdateProfile(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || r.URL.Path != "/v1/profile" {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		b := NewProfileBindings(newBindClientURL(t, srv.URL))
		err := b.UpdateProfile(signal.Profile{GivenName: "Bob", About: "Tester"})
		require.NoError(t, err)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		b := NewProfileBindings(newBindClientURL(t, srv.URL))
		err := b.UpdateProfile(signal.Profile{GivenName: "Charlie"})
		require.Error(t, err)
	})
}
