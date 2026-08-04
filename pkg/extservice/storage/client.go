// Package storage is the chat-server-side admin client for
// cmd/storage-service.
//
// Java reference: SecureStorageClient.java — one operation
// (DELETE /v1/storage) called when an account is deleted so the
// user's encrypted manifest + items are purged from storage-service's
// store.
//
// Authentication uses the same HMAC-derived Basic credentials the
// mobile client receives from /v1/storage/auth. signald presents
// username = accountUUID, password = HMAC-SHA256(sharedSecret,
// accountUUID) hex-encoded.
package storage

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/extservice/common"
)

// Client is the chat-server -> storage-service admin surface.
type Client interface {
	// DeleteStoredData asks storage-service to purge all manifest +
	// items for the given account. Idempotent: removing a
	// non-existent record is a success.
	DeleteStoredData(ctx context.Context, accountUUID string) error
	// Close releases the underlying transport's idle connections.
	Close() error
}

// HTTPConfig configures the HTTP client.
type HTTPConfig struct {
	BaseURL      string
	SharedSecret string
	Timeout      time.Duration
	TLSConfig    *tls.Config
}

// HTTPClient implements Client by issuing DELETE /v1/storage requests.
type HTTPClient struct {
	baseURL string
	secret  []byte
	timeout time.Duration
	http    *http.Client
}

// NewHTTP constructs an HTTPClient.
func NewHTTP(cfg HTTPConfig) (*HTTPClient, error) {
	if cfg.BaseURL == "" {
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "storage: BaseURL is required")
	}
	if cfg.SharedSecret == "" {
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "storage: SharedSecret is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tlsCfg := cfg.TLSConfig
	if tlsCfg == nil {
		// Java uses TLS 1.3 for storage-service.
		tlsCfg = &tls.Config{MinVersion: tls.VersionTLS13}
	}
	return &HTTPClient{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		secret:  []byte(cfg.SharedSecret),
		timeout: timeout,
		http: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}, nil
}

// DeleteStoredData issues DELETE /v1/storage with HMAC Basic auth.
// 404 is treated as success per the Java reference.
func (c *HTTPClient) DeleteStoredData(ctx context.Context, accountUUID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/v1/storage", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", common.BasicAuthHeader(accountUUID, c.secret))
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return nil
	default:
		return &Error{StatusCode: resp.StatusCode, Message: "storage-service admin call failed"}
	}
}

// Close releases the underlying HTTP transport's idle connections.
func (c *HTTPClient) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

// Error captures a non-success response from storage-service.
type Error struct {
	StatusCode int
	Message    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("storage-service: %s (status=%d)", e.Message, e.StatusCode)
}

// NoopClient is a Client that never makes network calls — used by
// monolithic deployments and unit tests that don't exercise the
// chat-server -> storage-service boundary.
type NoopClient struct{}

// NewNoop returns a NoopClient.
func NewNoop() *NoopClient { return &NoopClient{} }

// DeleteStoredData is a no-op.
func (NoopClient) DeleteStoredData(_ context.Context, _ string) error { return nil }

// Close is a no-op.
func (NoopClient) Close() error { return nil }

// ErrUnavailable is returned by the typed-nil pattern when callers
// have no client configured (monolithic deployment). Helpers in
// signald check for nil and fall back to NoopClient.
var ErrUnavailable = errors.New("storage-service client unavailable")
