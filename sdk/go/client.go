package signal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-libsignal/pkg/logger"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// noopLogger suppresses all go-libsignal debug output.
type noopLogger struct{}

func (noopLogger) Debug(_, _ string)   {}
func (noopLogger) Info(_, _ string)    {}
func (noopLogger) Warning(_, _ string) {}
func (noopLogger) Error(_, _ string)   {}
func (noopLogger) Configure(_ string)  {}

func init() {
	var l logger.Loggable = noopLogger{}
	logger.Setup(&l)
}

// Client is the main entry point for the Signal SDK. All sensitive material
// is held in protected memory and zeroed on Close().
type Client struct {
	config     ClientConfig
	httpClient *http.Client
	store      Store
	crypto     *cryptoState
}

// NewClient creates a new Signal client with the given configuration. ctx
// bounds reading the protected CA certificate and loading saved credentials.
// rootCAs builds the trust pool for a configured CA certificate. A CA that was
// never configured yields a nil pool, meaning the system roots; that is the only
// case that may. A configured CA that cannot be opened or holds no certificate
// is an error: falling back to the system roots would verify the server against
// a trust anchor the caller did not choose.
func rootCAs(ctx context.Context, ca *secrets.SecureString) (*x509.CertPool, error) {
	if ca == nil || ca.IsAbsent() {
		return nil, nil
	}
	pool := x509.NewCertPool()
	parsed := false
	if err := ca.TryWithBytes(ctx, func(pem []byte) {
		parsed = pool.AppendCertsFromPEM(pem)
	}); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrUnavailable, "signal: open CA certificate", err)
	}
	if !parsed {
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "signal: failed to parse CA certificate")
	}
	return pool, nil
}

func NewClient(ctx context.Context, cfg ClientConfig) (*Client, error) {
	if cfg.ServerURL == "" {
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "signal: ServerURL is required")
	}
	if cfg.DataDir == "" {
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "signal: DataDir is required")
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "signal-go-sdk/0.1"
	}

	// Build HTTP client with optional custom CA.
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	pool, err := rootCAs(ctx, cfg.CACert)
	if err != nil {
		return nil, err
	}
	tlsConfig.RootCAs = pool

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	store := cfg.Store
	if store == nil {
		daoStore, err := NewDefaultDAOStore(cfg.DataDir)
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "signal: create dao store", err)
		}
		store = daoStore
	}

	// Load saved credentials if available.
	creds, err := store.GetCredentials(ctx)
	if err == nil && creds != nil {
		if cfg.Account == "" {
			cfg.Account = creds.Number
		}
		if cfg.Password == nil || cfg.Password.IsDestroyed(ctx) {
			cfg.Password = creds.Password
		}
		if cfg.DeviceID == 0 {
			cfg.DeviceID = creds.DeviceID
		}
	}

	return &Client{
		config:     cfg,
		httpClient: httpClient,
		store:      store,
	}, nil
}

// Close releases all resources and wipes sensitive material from memory.
func (c *Client) Close() error {
	c.config.Destroy()
	if c.store != nil {
		return c.store.Close()
	}
	return nil
}

// Config returns the client configuration.
func (c *Client) Config() ClientConfig {
	return c.config
}

// getPassword extracts the password from SecureString for use in HTTP auth.
// The returned string should be used immediately and not stored.
func (c *Client) getPassword(ctx context.Context) string {
	if c.config.Password == nil {
		return ""
	}
	return c.config.Password.Plaintext(ctx)
}

// NewSecurePassword creates a SecureString from a plain password string,
// wiping the source. Convenience for CLI flag → SecureString conversion.
// An empty password, or a failure to obtain a protected allocation, is
// returned as an error rather than yielding an unusable credential.
func NewSecurePassword(ctx context.Context, password string) (*secrets.SecureString, error) {
	return secrets.NewSecureString(ctx, password)
}
