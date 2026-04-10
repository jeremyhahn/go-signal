package signal

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

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
// is held in memguard-protected memory and zeroed on Close().
type Client struct {
	config     ClientConfig
	httpClient *http.Client
	store      Store
	crypto     *cryptoState
}

// NewClient creates a new Signal client with the given configuration.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("signal: ServerURL is required")
	}
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("signal: DataDir is required")
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "signal-go-sdk/0.1"
	}

	// Build HTTP client with optional custom CA.
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.CACert != nil && !cfg.CACert.IsDestroyed() {
		caBytes := cfg.CACert.Bytes()
		if caBytes != nil {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caBytes) {
				for i := range caBytes {
					caBytes[i] = 0
				}
				return nil, fmt.Errorf("signal: failed to parse CA certificate")
			}
			tlsConfig.RootCAs = pool
			for i := range caBytes {
				caBytes[i] = 0
			}
		}
	}

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
			return nil, fmt.Errorf("signal: create dao store: %w", err)
		}
		store = daoStore
	}

	// Load saved credentials if available.
	creds, err := store.GetCredentials()
	if err == nil && creds != nil {
		if cfg.Account == "" {
			cfg.Account = creds.Number
		}
		if cfg.Password == nil || cfg.Password.IsDestroyed() {
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
func (c *Client) getPassword() string {
	if c.config.Password == nil {
		return ""
	}
	return c.config.Password.Plaintext()
}

// NewSecurePassword creates a SecureString from a plain password string,
// wiping the source. Convenience for CLI flag → SecureString conversion.
func NewSecurePassword(password string) *secrets.SecureString {
	return secrets.NewSecureString(password)
}
