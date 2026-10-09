package signal

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// countingServer records how many requests reach it.
func countingServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestDoRequest_UnopenablePasswordIsAnError: a configured password that would
// not open used to read as "", so the request went out with no Authorization
// header and surfaced as an unrelated 401 (or, on a public route, succeeded
// unauthenticated).
func TestDoRequest_UnopenablePasswordIsAnError(t *testing.T) {
	srv, hits := countingServer(t)
	c := newTestClient(t, srv.URL, &mockStore{})
	c.config.Password = secrets.MustNewSecureString(t.Context(), "token")
	defer c.config.Password.Destroy()

	err := c.doRequest(canceledCtx(), http.MethodGet, "/v1/accounts/whoami", nil, nil)

	var unavailable *secrets.UnavailableSecretError
	require.ErrorAs(t, err, &unavailable)
	require.Zero(t, hits.Load(), "a request was sent despite the failure")
}

// TestDoRequest_NoPasswordSendsUnauthenticated: a password that was never set is
// the one case that legitimately sends no Authorization header.
func TestDoRequest_NoPasswordSendsUnauthenticated(t *testing.T) {
	srv, hits := countingServer(t)
	c := newTestClient(t, srv.URL, &mockStore{})
	c.config.Password = nil

	require.NoError(t, c.doRequest(t.Context(), http.MethodGet, "/v1/ping", nil, nil))
	require.EqualValues(t, 1, hits.Load())
}

// TestConnectWebSocketSession_UnopenablePasswordIsAnError: the dialer must not
// authenticate with an empty password.
func TestConnectWebSocketSession_UnopenablePasswordIsAnError(t *testing.T) {
	srv, hits := countingServer(t)
	password := secrets.MustNewSecureString(t.Context(), "token")
	defer password.Destroy()
	c := newTestClient(t, srv.URL, &mockStore{credentials: &Credentials{UUID: "u", DeviceID: 1, Password: password}})

	_, err := c.ConnectWebSocketSession(canceledCtx(), func(ReceivedMessage) {})

	var unavailable *secrets.UnavailableSecretError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %T (%v), want it to wrap *UnavailableSecretError", err, err)
	}
	require.Zero(t, hits.Load(), "the server was dialed despite the failure")
}
