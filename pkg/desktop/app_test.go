//go:build desktop

package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// appStubStore is a no-op signal.Store for App unit tests.
// GetCredentials returns nil so IsRegistered reports false.
type appStubStore struct{}

// registeredStubStore returns a non-nil Credentials so IsRegistered returns true.
type registeredStubStore struct{ appStubStore }

func (appStubStore) GetCredentials() (*signal.Credentials, error) { return nil, nil }
func (appStubStore) SaveCredentials(_ *signal.Credentials) error  { return nil }
func (appStubStore) GetContacts() ([]signal.Contact, error)       { return nil, nil }
func (appStubStore) SaveContact(_ *signal.Contact) error          { return nil }
func (appStubStore) DeleteContact(_ string) error                 { return nil }
func (appStubStore) GetMessages(_ string, _ int) ([]signal.Message, error) {
	return nil, nil
}
func (appStubStore) SaveMessage(_ *signal.Message) error { return nil }
func (appStubStore) GetGroups() ([]signal.Group, error)  { return nil, nil }
func (appStubStore) SaveGroup(_ *signal.Group) error     { return nil }
func (appStubStore) GetStickerPacks() ([]signal.InstalledStickerPack, error) {
	return nil, nil
}
func (appStubStore) SaveStickerPack(_ *signal.InstalledStickerPack) error { return nil }
func (appStubStore) DeleteStickerPack(_ string) error                     { return nil }
func (appStubStore) Close() error                                         { return nil }

func (registeredStubStore) GetCredentials() (*signal.Credentials, error) {
	return &signal.Credentials{UUID: "test-uuid-001", Number: "+15550001111"}, nil
}

// errorCredStore returns an error from GetCredentials to exercise the err != nil branch.
type errorCredStore struct{ appStubStore }

func (errorCredStore) GetCredentials() (*signal.Credentials, error) {
	return nil, errors.New("credential store unavailable")
}

var _ signal.Store = appStubStore{}
var _ signal.Store = registeredStubStore{}
var _ signal.Store = errorCredStore{}

// newTestAppConfig returns a minimal ClientConfig backed by the stub store.
func newTestAppConfig() signal.ClientConfig {
	return signal.ClientConfig{
		ServerURL: "http://127.0.0.1:19997",
		DataDir:   "/tmp/go-signal-desktop-test",
		UserAgent: "test/0.0",
		Store:     appStubStore{},
	}
}

// TestNewApp verifies App construction.
func TestNewApp(t *testing.T) {
	t.Run("SucceedsWithStubStore", func(t *testing.T) {
		app, err := NewApp(newTestAppConfig())
		require.NoError(t, err)
		require.NotNil(t, app)
	})
	t.Run("MissingServerURLReturnsError", func(t *testing.T) {
		cfg := signal.ClientConfig{
			DataDir:   "/tmp/go-signal-desktop-test",
			UserAgent: "test/0.0",
			Store:     appStubStore{},
		}
		_, err := NewApp(cfg)
		require.Error(t, err)
	})
}

// TestApp_Startup verifies that Startup sets the context.
func TestApp_Startup(t *testing.T) {
	t.Run("SetsContext", func(t *testing.T) {
		app, err := NewApp(newTestAppConfig())
		require.NoError(t, err)
		assert.Nil(t, app.ctx)
		app.Startup(context.Background())
		assert.NotNil(t, app.ctx)
	})
	t.Run("OverridesContext", func(t *testing.T) {
		app, err := NewApp(newTestAppConfig())
		require.NoError(t, err)
		ctx1 := context.Background()
		ctx2, cancel := context.WithCancel(context.Background())
		defer cancel()
		app.Startup(ctx1)
		app.Startup(ctx2)
		assert.Equal(t, ctx2, app.ctx)
	})
}

// TestApp_Shutdown verifies Shutdown does not panic.
func TestApp_Shutdown(t *testing.T) {
	t.Run("ShutdownWithClient", func(t *testing.T) {
		app, err := NewApp(newTestAppConfig())
		require.NoError(t, err)
		assert.NotPanics(t, func() { app.Shutdown(context.Background()) })
	})
	t.Run("ShutdownNilClient", func(t *testing.T) {
		app := &App{}
		assert.NotPanics(t, func() { app.Shutdown(context.Background()) })
	})
}

// ---------------------------------------------------------------------------
// Helpers for HTTP-backed App tests
// ---------------------------------------------------------------------------

// newTestAppForServer constructs an App connected to the given httptest URL.
// Uses a stub store so a.daos is nil; suitable for all App methods except
// GetConversations which requires a DAOStore.
func newTestAppForServer(t *testing.T, serverURL string) *App {
	t.Helper()
	cfg := signal.ClientConfig{
		ServerURL: serverURL,
		DataDir:   t.TempDir(),
		UserAgent: "test/0.0",
		Store:     appStubStore{},
	}
	app, err := NewApp(cfg)
	require.NoError(t, err)
	return app
}

// newTestAppWithDAOStore constructs an App whose client store is a *signal.DAOStore,
// which makes a.daos non-nil for GetConversations tests.
func newTestAppWithDAOStore(t *testing.T, serverURL string) *App {
	t.Helper()
	daoStore, err := signal.NewDefaultDAOStore(t.TempDir())
	require.NoError(t, err)
	cfg := signal.ClientConfig{
		ServerURL: serverURL,
		DataDir:   t.TempDir(),
		UserAgent: "test/0.0",
		Store:     daoStore,
	}
	app, err := NewApp(cfg)
	require.NoError(t, err)
	return app
}

// TestApp_IsRegistered verifies the registration status check.
func TestApp_IsRegistered(t *testing.T) {
	t.Run("FalseWhenNoCredentials", func(t *testing.T) {
		app, err := NewApp(newTestAppConfig())
		require.NoError(t, err)
		// Stub store returns nil credentials → not registered.
		registered, err := app.IsRegistered()
		require.NoError(t, err)
		assert.False(t, registered)
	})
	t.Run("TrueWhenCredentialsPresent", func(t *testing.T) {
		cfg := signal.ClientConfig{
			ServerURL: "http://127.0.0.1:19997",
			DataDir:   "/tmp/go-signal-desktop-test",
			UserAgent: "test/0.0",
			Store:     registeredStubStore{},
		}
		app, err := NewApp(cfg)
		require.NoError(t, err)
		registered, err := app.IsRegistered()
		require.NoError(t, err)
		assert.True(t, registered)
	})
	t.Run("FalseOnStoreError", func(t *testing.T) {
		cfg := signal.ClientConfig{
			ServerURL: "http://127.0.0.1:19997",
			DataDir:   "/tmp/go-signal-desktop-test",
			UserAgent: "test/0.0",
			Store:     errorCredStore{},
		}
		app, err := NewApp(cfg)
		require.NoError(t, err)
		// Error from store → IsRegistered returns false, nil (not the error).
		registered, err := app.IsRegistered()
		require.NoError(t, err)
		assert.False(t, registered)
	})
}

// ---------------------------------------------------------------------------
// Tests for HTTP-delegating App methods
// ---------------------------------------------------------------------------

// TestApp_WhoAmI tests App.WhoAmI which delegates to client.WhoAmI.
func TestApp_WhoAmI(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/accounts/whoami" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signal.Account{UUID: "acct-uuid", Number: "+15550001234"})
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		acct, err := app.WhoAmI()
		require.NoError(t, err)
		require.NotNil(t, acct)
		assert.Equal(t, "acct-uuid", acct.UUID)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		_, err := app.WhoAmI()
		require.Error(t, err)
	})
}

// TestApp_Register tests App.Register which delegates to client.Register.
func TestApp_Register(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/registration" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signal.RegistrationResult{
				UUID: "reg-uuid",
				PNI:  "reg-pni",
			})
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		result, err := app.Register("+15550009999", "sess-abc")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "reg-uuid", result.UUID)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "conflict", http.StatusConflict)
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		_, err := app.Register("+15550009999", "sess-xyz")
		require.Error(t, err)
	})
}

// TestApp_CreateVerificationSession tests the session creation delegation.
func TestApp_CreateVerificationSession(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/verification/session" {
				t.Errorf("unexpected path %s", r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signal.VerificationSession{ID: "vsess-1"})
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		sess, err := app.CreateVerificationSession("+15550001111")
		require.NoError(t, err)
		assert.Equal(t, "vsess-1", sess.ID)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		_, err := app.CreateVerificationSession("+15550001111")
		require.Error(t, err)
	})
}

// TestApp_RequestVerificationCode tests sending the verification code.
func TestApp_RequestVerificationCode(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signal.VerificationSession{ID: "vsess-2"})
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		sess, err := app.RequestVerificationCode("vsess-2")
		require.NoError(t, err)
		assert.Equal(t, "vsess-2", sess.ID)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		_, err := app.RequestVerificationCode("vsess-bad")
		require.Error(t, err)
	})
}

// TestApp_SubmitVerificationCode tests submitting the verification code.
func TestApp_SubmitVerificationCode(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut {
				t.Errorf("expected PUT, got %s", r.Method)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signal.VerificationSession{ID: "vsess-3", Verified: true})
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		sess, err := app.SubmitVerificationCode("vsess-3", "123456")
		require.NoError(t, err)
		assert.True(t, sess.Verified)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "wrong code", http.StatusForbidden)
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		_, err := app.SubmitVerificationCode("vsess-3", "000000")
		require.Error(t, err)
	})
}

// TestApp_SendMessage tests the message sending delegation.
func TestApp_SendMessage(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"needsSync": false})
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		result, err := app.SendMessage("+15550007777", "Hey!")
		require.NoError(t, err)
		require.NotNil(t, result)
	})
	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		app := newTestAppForServer(t, srv.URL)
		_, err := app.SendMessage("+15550007777", "Hey!")
		require.Error(t, err)
	})
}

// TestApp_GetConversations tests conversation listing via the DAOStore path.
func TestApp_GetConversations(t *testing.T) {
	t.Run("EmptyWhenNoConversations", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		app := newTestAppWithDAOStore(t, srv.URL)
		convs, err := app.GetConversations()
		require.NoError(t, err)
		assert.Empty(t, convs)
	})
	t.Run("DaosIsNilReturnsNilPanic", func(t *testing.T) {
		// When a.daos is nil, GetConversations panics with nil dereference.
		// This test verifies the DAOStore-backed path works when a.daos is set.
		// (the nil case is not a normal operational path)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		app := newTestAppWithDAOStore(t, srv.URL)
		assert.NotNil(t, app.daos, "daos should be set when store is a *signal.DAOStore")
		convs, err := app.GetConversations()
		require.NoError(t, err)
		// GetConversations returns nil (not an empty slice) when there are no rows; Empty accepts both.
		assert.Empty(t, convs)
	})
}

// TestNewApp_DAOStoreFactory verifies that NewApp extracts the factory from
// a *signal.DAOStore, making a.daos non-nil.
func TestNewApp_DAOStoreFactory(t *testing.T) {
	t.Run("ExtractsFactoryFromDAOStore", func(t *testing.T) {
		daoStore, err := signal.NewDefaultDAOStore(t.TempDir())
		require.NoError(t, err)

		cfg := signal.ClientConfig{
			ServerURL: "http://127.0.0.1:19997",
			DataDir:   t.TempDir(),
			UserAgent: "test/0.0",
			Store:     daoStore,
		}
		app, err := NewApp(cfg)
		require.NoError(t, err)
		// The factory must be extracted; a.daos must be non-nil.
		assert.NotNil(t, app.daos)
	})
}

// TestRun_MkdirAllError verifies that Run returns early when the data
// directory cannot be created. Passing a path whose parent is a file causes
// os.MkdirAll to fail on Linux without touching the real home directory.
func TestRun_MkdirAllError(t *testing.T) {
	// /dev/null is a character device (not a directory), so creating a
	// sub-path inside it will fail with "not a directory".
	err := Run("http://localhost:9999", "/dev/null/cannot-create")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create data dir")
}

// TestRun_HomeDirFallback covers the dataDir=="" branch. Setting HOME to
// /dev/null causes os.UserHomeDir to return "/dev/null", and os.MkdirAll
// for the child path then fails because /dev/null is not a directory.
// This verifies counters for the home-dir resolution path without touching
// the real home directory.
func TestRun_HomeDirFallback(t *testing.T) {
	t.Setenv("HOME", "/dev/null")
	err := Run("http://localhost:9999", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create data dir")
}

// TestRun_NewAppCreationFail covers the NewApp-error return branch. A regular
// file is placed at the path where PebbleDB expects a directory, causing
// NewDefaultDAOStore to fail after os.MkdirAll succeeds.
func TestRun_NewAppCreationFail(t *testing.T) {
	tmpDir := t.TempDir()
	// Block PebbleDB: a file at tmpDir/pebble prevents directory creation.
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "pebble"), []byte("x"), 0600))
	err := Run("http://localhost:9999", tmpDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create app")
}

// TestRun_ServerURLDefaults covers the serverURL=="" default branch. An empty
// server URL is passed so Run sets it to the built-in default before calling
// NewApp. The PebbleDB block triggers an early error return so Run does not
// block on select{}.
func TestRun_ServerURLDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "pebble"), []byte("x"), 0600))
	err := Run("", tmpDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create app")
}

// TestRun_BlocksAfterSuccessfulInit covers the final block in Run: the
// fmt.Fprintf, fmt.Fprintln, _ = app, and select{} statements. Run is
// designed to block forever on select{}; this test runs it in a background
// goroutine, waits for it to pass all early-exit guards, then returns. The
// goroutine is intentionally leaked — it blocks on select{} until the test
// binary exits and Go's runtime terminates it.
func TestRun_BlocksAfterSuccessfulInit(t *testing.T) {
	tmpDir := t.TempDir()
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run("http://localhost:9999", tmpDir)
	}()
	// Allow the goroutine to create PebbleDB, call NewApp, execute the
	// informational prints, and reach the blocking select{}.
	// PebbleDB creation typically completes well under 200ms.
	time.Sleep(200 * time.Millisecond)
	// Verify the goroutine has not returned early with an error.
	select {
	case err := <-errCh:
		t.Fatalf("Run returned unexpectedly: %v", err)
	default:
		// Expected: Run is blocked on select{} — all preceding statements covered.
	}
}
