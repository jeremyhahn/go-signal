//go:build desktop

package bindings

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMessagingBindings verifies construction.
func TestNewMessagingBindings(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		b := NewMessagingBindings(newBindClient(t), newTestBindFactory(t))
		require.NotNil(t, b)
	})
	t.Run("RetainsDependencies", func(t *testing.T) {
		c := newBindClient(t)
		f := newTestBindFactory(t)
		b := NewMessagingBindings(c, f)
		require.NotNil(t, b.client)
		require.NotNil(t, b.factory)
	})
}

// TestMessagingBindings_SendMessage tests sending a message via the REST API.
func TestMessagingBindings_SendMessage(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		// Send() first GETs /v2/keys/<recipient>/1 to establish a session.
		// Returning 404 causes the SDK to fall back to plaintext and then
		// PUT /v1/messages/<recipient>.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/keys/"):
				// No pre-key bundle → SDK falls back to plaintext send.
				http.Error(w, "not found", http.StatusNotFound)
			case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/messages/"):
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"needsSync": false})
			default:
				http.Error(w, "unexpected path", http.StatusNotFound)
			}
		}))
		defer srv.Close()

		b := NewMessagingBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		result, err := b.SendMessage("+15550001111", "Hello!", nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.GreaterOrEqual(t, result.Timestamp, int64(0))
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		b := NewMessagingBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		_, err := b.SendMessage("+15550001111", "Hello!", nil)
		require.Error(t, err)
	})
}

// TestMessagingBindings_SendMessage_ExistingConversation tests the conversation
// update branch when a conversation already exists for the recipient.
func TestMessagingBindings_SendMessage_ExistingConversation(t *testing.T) {
	t.Run("UpdatesExistingConversation", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/keys/"):
				http.Error(w, "not found", http.StatusNotFound)
			default:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"needsSync": false})
			}
		}))
		defer srv.Close()

		factory := newTestBindFactory(t)
		b := NewMessagingBindings(newBindClientURL(t, srv.URL), factory)

		// Pre-seed a conversation so the update branch executes.
		convBinding := NewConversationBindings(factory)
		seedConversation(t, convBinding, "+15550099999")

		result, err := b.SendMessage("+15550099999", "Update!", nil)
		require.NoError(t, err)
		require.NotNil(t, result)
	})
}

// TestMessagingBindings_SendReaction tests sending an emoji reaction.
func TestMessagingBindings_SendReaction(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/v1/messages/") {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		b := NewMessagingBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		err := b.SendReaction("+15550002222", "👍", 1234567890)
		require.NoError(t, err)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		b := NewMessagingBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		err := b.SendReaction("+15550002222", "❤️", 9876543210)
		require.Error(t, err)
	})
}

// TestMessagingBindings_SendTyping tests sending a typing indicator.
func TestMessagingBindings_SendTyping(t *testing.T) {
	t.Run("StartedSuccess", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		b := NewMessagingBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		require.NoError(t, b.SendTyping("+15550003333", true))
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		b := NewMessagingBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		require.Error(t, b.SendTyping("+15550003333", false))
	})
}

// TestMessagingBindings_SendReadReceipt tests sending read receipts.
func TestMessagingBindings_SendReadReceipt(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		b := NewMessagingBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		require.NoError(t, b.SendReadReceipt("+15550004444", []int64{100, 200, 300}))
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusBadGateway)
		}))
		defer srv.Close()

		b := NewMessagingBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		require.Error(t, b.SendReadReceipt("+15550004444", []int64{999}))
	})
}

// TestMessagingBindings_RemoteDelete tests remote message deletion.
func TestMessagingBindings_RemoteDelete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		b := NewMessagingBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		require.NoError(t, b.RemoteDelete("+15550005555", 1234567890))
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		b := NewMessagingBindings(newBindClientURL(t, srv.URL), newTestBindFactory(t))
		require.Error(t, b.RemoteDelete("+15550005555", 9876543210))
	})
}
