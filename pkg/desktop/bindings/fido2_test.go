//go:build desktop && fido2

package bindings

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// TestNewFIDO2Bindings verifies construction.
// Methods that call signal.Client (FIDO2Capabilities, FIDO2ListCredentials,
// FIDO2BeginRegistration, FIDO2BeginLogin, FIDO2DeleteCredential,
// FIDO2RenameCredential) require a live server and are not unit-testable.
func TestNewFIDO2Bindings(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		b := NewFIDO2Bindings(newBindClient(t))
		require.NotNil(t, b)
	})
	t.Run("RetainsClient", func(t *testing.T) {
		c := newBindClient(t)
		b := NewFIDO2Bindings(c)
		require.NotNil(t, b.client)
	})
}

// TestFIDO2Bindings_FinishRegistration tests JSON parsing before the
// client call. The client call itself will fail (no server), but the
// JSON validation layer IS unit-testable.
func TestFIDO2Bindings_FinishRegistration(t *testing.T) {
	t.Run("InvalidJSONReturnsError", func(t *testing.T) {
		b := NewFIDO2Bindings(newBindClient(t))
		err := b.FIDO2FinishRegistration("session-1", "{not-valid-json")
		require.Error(t, err)
	})
	t.Run("ValidJSONProceedsToClientCall", func(t *testing.T) {
		b := NewFIDO2Bindings(newBindClient(t))
		// Valid JSON — JSON parsing succeeds; the client call will fail
		// with a network error (no server) rather than a JSON parse error.
		err := b.FIDO2FinishRegistration("session-2", `{"id":"abc","type":"public-key"}`)
		// Must NOT be a JSON error; it will be a network/auth error from the client.
		if err != nil {
			assert.NotContains(t, err.Error(), "invalid character")
		}
	})
}

// TestFIDO2Bindings_FinishLogin tests JSON parsing before the client call.
func TestFIDO2Bindings_FinishLogin(t *testing.T) {
	t.Run("InvalidJSONReturnsError", func(t *testing.T) {
		b := NewFIDO2Bindings(newBindClient(t))
		err := b.FIDO2FinishLogin("not-json-at-all")
		require.Error(t, err)
	})
	t.Run("ValidJSONProceedsToClientCall", func(t *testing.T) {
		b := NewFIDO2Bindings(newBindClient(t))
		err := b.FIDO2FinishLogin(`{"id":"cred-id","type":"public-key"}`)
		// Network/auth failure expected — not a JSON parse failure.
		if err != nil {
			assert.NotContains(t, err.Error(), "invalid character")
		}
	})
}

// TestFIDO2Bindings_FIDO2Capabilities tests the server capabilities query.
func TestFIDO2Bindings_FIDO2Capabilities(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/fido2/capabilities" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"attestation": "direct"})
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		caps, err := b.FIDO2Capabilities()
		require.NoError(t, err)
		assert.NotNil(t, caps)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		_, err := b.FIDO2Capabilities()
		require.Error(t, err)
	})
}

// TestFIDO2Bindings_FIDO2ListCredentials tests credential list retrieval.
func TestFIDO2Bindings_FIDO2ListCredentials(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/fido2/credentials" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"credentials": []signal.FIDO2Credential{{CredentialID: "cred-1", Name: "Key A"}},
			})
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		creds, err := b.FIDO2ListCredentials()
		require.NoError(t, err)
		assert.Len(t, creds, 1)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusUnauthorized)
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		_, err := b.FIDO2ListCredentials()
		require.Error(t, err)
	})
}

// TestFIDO2Bindings_FIDO2BeginRegistration tests starting the registration ceremony.
func TestFIDO2Bindings_FIDO2BeginRegistration(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/fido2/session" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": "abc123"})
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		options, err := b.FIDO2BeginRegistration("alice@example.com")
		require.NoError(t, err)
		assert.NotNil(t, options)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		_, err := b.FIDO2BeginRegistration("bob@example.com")
		require.Error(t, err)
	})
}

// TestFIDO2Bindings_FIDO2BeginLogin tests starting the login ceremony.
func TestFIDO2Bindings_FIDO2BeginLogin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/fido2/login/begin" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge": "def456"})
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		options, err := b.FIDO2BeginLogin()
		require.NoError(t, err)
		assert.NotNil(t, options)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		_, err := b.FIDO2BeginLogin()
		require.Error(t, err)
	})
}

// TestFIDO2Bindings_FIDO2DeleteCredential tests removing a security key.
func TestFIDO2Bindings_FIDO2DeleteCredential(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete || !strings.HasPrefix(r.URL.Path, "/v1/fido2/credentials/") {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		require.NoError(t, b.FIDO2DeleteCredential("cred-to-delete"))
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusNotFound)
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		require.Error(t, b.FIDO2DeleteCredential("missing-cred"))
	})
}

// TestFIDO2Bindings_FIDO2RenameCredential tests renaming a security key.
func TestFIDO2Bindings_FIDO2RenameCredential(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || !strings.Contains(r.URL.Path, "/name") {
				t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		require.NoError(t, b.FIDO2RenameCredential("cred-abc", "My YubiKey"))
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		b := NewFIDO2Bindings(newBindClientURL(t, srv.URL))
		require.Error(t, b.FIDO2RenameCredential("cred-abc", "renamed"))
	})
}
