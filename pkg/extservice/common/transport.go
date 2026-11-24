package common

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TLSConfig captures the inter-service TLS policy. Production
// deployments populate the cert paths so mTLS is enforced; dev /
// docker-compose deployments flip Insecure to true. Pure pass-through
// helpers below return *tls.Config or grpc.DialOption ready to use.
type TLSConfig struct {
	// CAFile is the PEM-encoded root CA to validate the server with.
	// When empty the system root store is used.
	CAFile string
	// ClientCertFile + ClientKeyFile enable mTLS: the chat-server
	// presents its own cert to the external service. Both must be
	// set; both empty means TLS-only (no client cert).
	ClientCertFile string
	ClientKeyFile  string
	// MinVersion defaults to TLS 1.2. Set to tls.VersionTLS13 for
	// services that require it (storage-service mirrors Java's
	// TLS 1.3 requirement).
	MinVersion uint16
	// Insecure permits a plaintext channel — only valid for
	// development and docker-compose. Production deployments must
	// leave this false.
	Insecure bool
}

// HTTPTransport returns an *http.Transport configured for the given
// TLS policy. Returns nil + error when Insecure is false and required
// cert material is missing.
func (c TLSConfig) HTTPTransport() (*http.Transport, error) {
	if c.Insecure {
		// Insecure mode is opt-in for dev / docker-compose; production
		// callers leave the field false and supply TLS material.
		// #nosec G402 -- Insecure path is intentional.
		return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, nil
	}
	cfg, err := c.buildTLSConfig()
	if err != nil {
		return nil, err
	}
	return &http.Transport{TLSClientConfig: cfg}, nil
}

// GRPCDialOption returns the grpc.DialOption set for the given TLS
// policy. The single option encapsulates both the credential type
// and any mTLS material.
func (c TLSConfig) GRPCDialOption() (grpc.DialOption, error) {
	if c.Insecure {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}
	cfg, err := c.buildTLSConfig()
	if err != nil {
		return nil, err
	}
	return grpc.WithTransportCredentials(credentials.NewTLS(cfg)), nil
}

func (c TLSConfig) buildTLSConfig() (*tls.Config, error) {
	minVer := c.MinVersion
	if minVer == 0 {
		minVer = tls.VersionTLS12
	}
	// Caller controls MinVersion via the TLSConfig field; defaulting
	// to TLS 1.2 matches Java's reference clients.
	// #nosec G402 -- MinVersion is parameterised.
	cfg := &tls.Config{MinVersion: minVer}

	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("extservice: failed to parse CA bundle")
		}
		cfg.RootCAs = pool
	}

	hasCert := c.ClientCertFile != ""
	hasKey := c.ClientKeyFile != ""
	if hasCert != hasKey {
		return nil, errors.New("extservice: both ClientCertFile and ClientKeyFile must be set for mTLS")
	}
	if hasCert {
		cert, err := tls.LoadX509KeyPair(c.ClientCertFile, c.ClientKeyFile)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

// DefaultDeadlines returns the default RPC + connect timeouts for
// inter-service calls. Java's reference clients use 10s connect / 15s
// per-RPC; we adopt the same to keep operator runbooks aligned.
func DefaultDeadlines() (connect, rpc time.Duration) {
	return 10 * time.Second, 15 * time.Second
}
