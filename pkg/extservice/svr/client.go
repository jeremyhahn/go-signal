// Package svr is the chat-server-side admin client for cmd/svr2.
//
// Java reference: SecureValueRecoveryClient.java — one operation
// (DELETE /v1/delete) called when an account is deleted so the user's
// secret-recovery record is purged from svr2's storage.
//
// Authentication uses the same HMAC-derived Basic credentials the
// mobile client receives from /v2/svr/auth. signald creates a username
// = the account identity, password = HMAC-SHA256(svrSharedSecret,
// username) hex-encoded.
package svr

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/extservice/common"
)

// Client is the chat-server -> svr2 admin surface.
type Client interface {
	// RemoveData asks svr2 to delete the record for the given
	// identity. Idempotent: removing a non-existent record is a
	// success.
	RemoveData(ctx context.Context, identity string) error
	// Close releases any underlying resources (HTTP transport
	// connections). Always safe to call.
	Close() error
}

// HTTPConfig configures the HTTP client.
type HTTPConfig struct {
	// BaseURL is the svr2 admin endpoint (e.g. https://svr2.example).
	// /v1/delete is appended at call time.
	BaseURL string
	// SharedSecret is the HMAC secret shared with svr2 for credential
	// derivation. Must match svr2.SVR2Config.SharedSecret.
	SharedSecret string
	// Timeout caps each RPC. Zero defaults to 5 seconds.
	Timeout time.Duration
	// TLSConfig overrides the default TLS config. When nil, system
	// CAs + TLS 1.2 minimum are used.
	TLSConfig *tls.Config
}

// HTTPClient implements Client by issuing HTTP DELETE requests to
// cmd/svr2's admin endpoint.
type HTTPClient struct {
	baseURL string
	secret  []byte
	timeout time.Duration
	http    *http.Client
}

// NewHTTP constructs an HTTPClient.
func NewHTTP(cfg HTTPConfig) (*HTTPClient, error) {
	if cfg.BaseURL == "" {
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "svr: BaseURL is required")
	}
	if cfg.SharedSecret == "" {
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "svr: SharedSecret is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tlsCfg := cfg.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &HTTPClient{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		secret:  []byte(cfg.SharedSecret),
		timeout: timeout,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
	}, nil
}

// RemoveData issues DELETE /v1/delete with HTTP Basic auth derived
// from identity. Non-2xx and non-404 responses become a typed error.
func (c *HTTPClient) RemoveData(ctx context.Context, identity string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v1/delete", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", common.BasicAuthHeader(identity, c.secret))
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		// Java mirror: 404 is allowed for already-absent records.
		return nil
	default:
		return &Error{StatusCode: resp.StatusCode, Message: "svr2 admin call failed"}
	}
}

// Close releases the underlying HTTP transport's idle connections.
func (c *HTTPClient) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

// Error captures a non-success response from svr2.
type Error struct {
	StatusCode int
	Message    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("svr2: %s (status=%d)", e.Message, e.StatusCode)
}

// NoopClient is a Client that never makes network calls — used by
// monolithic deployments and unit tests that don't exercise the
// chat-server->svr2 boundary.
type NoopClient struct{}

// NewNoop returns a NoopClient.
func NewNoop() *NoopClient { return &NoopClient{} }

// RemoveData is a no-op.
func (NoopClient) RemoveData(_ context.Context, _ string) error { return nil }

// Close is a no-op.
func (NoopClient) Close() error { return nil }
