package signal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestNewClient_UnopenableCACertIsAnError: a configured CA that cannot be
// opened used to leave RootCAs nil, so the client silently verified the server
// against the system roots instead of the pinned CA it was asked to trust.
func TestNewClient_UnopenableCACertIsAnError(t *testing.T) {
	ca := secrets.MustNewSecureString(t.Context(), "-----BEGIN CERTIFICATE-----")
	defer ca.Destroy()

	c, err := NewClient(canceledCtx(), ClientConfig{
		ServerURL: "https://localhost",
		DataDir:   t.TempDir(),
		Store:     &stubStore{},
		CACert:    ca,
	})

	var unavailable *secrets.UnavailableSecretError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %T (%v), want it to wrap *UnavailableSecretError", err, err)
	}
	if c != nil {
		t.Error("NewClient returned a client alongside the error")
	}
}

// TestNewClient_NoCACertUsesSystemRoots: not configuring a CA is the one case
// that legitimately leaves RootCAs unset.
func TestNewClient_NoCACertUsesSystemRoots(t *testing.T) {
	for name, ca := range map[string]*secrets.SecureString{
		"nil":   nil,
		"unset": {},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := NewClient(t.Context(), ClientConfig{
				ServerURL: "https://localhost",
				DataDir:   t.TempDir(),
				Store:     &stubStore{},
				CACert:    ca,
			})
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			_ = c.Close()
		})
	}
}

// TestConnectWebSocketSession_UnopenableCACertIsAnError covers the same path on
// the WebSocket dialer, which must fail before dialing.
func TestConnectWebSocketSession_UnopenableCACertIsAnError(t *testing.T) {
	dialed := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		dialed = true
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &mockStore{credentials: &Credentials{UUID: "u", DeviceID: 1}})
	c.config.CACert = secrets.MustNewSecureString(t.Context(), "-----BEGIN CERTIFICATE-----")
	defer c.config.CACert.Destroy()

	_, err := c.ConnectWebSocketSession(canceledCtx(), func(ReceivedMessage) {})

	var unavailable *secrets.UnavailableSecretError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %T (%v), want it to wrap *UnavailableSecretError", err, err)
	}
	if dialed {
		t.Error("the server was dialed despite the CA failure")
	}
}

// TestConnectWebSocketSession_InvalidCACertIsAnError: a CA that opens but holds
// no certificate must fail, not dial with an empty pool.
func TestConnectWebSocketSession_InvalidCACertIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &mockStore{credentials: &Credentials{UUID: "u", DeviceID: 1}})
	c.config.CACert = secrets.MustNewSecureString(t.Context(), "not-a-certificate")
	defer c.config.CACert.Destroy()

	_, err := c.ConnectWebSocketSession(t.Context(), func(ReceivedMessage) {})
	if err == nil {
		t.Fatal("expected an error for a CA with no certificate")
	}
}
