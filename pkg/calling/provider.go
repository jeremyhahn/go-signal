package calling

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TurnCredentialProvider abstracts retrieval of TURN relay credentials. This
// interface enables testability by allowing mock implementations.
type TurnCredentialProvider interface {
	RetrieveCredentials(ctx context.Context) (*TurnToken, error)
}

// cloudflareCredentialRequest is the JSON body sent to Cloudflare TURN API.
type cloudflareCredentialRequest struct {
	TTL int64 `json:"ttl"`
}

// cloudflareResponse is the Cloudflare TURN API response shape.
type cloudflareResponse struct {
	IceServers cloudflareIceServer `json:"iceServers"`
}

// cloudflareIceServer contains the ICE server credentials from Cloudflare.
type cloudflareIceServer struct {
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
	URLs       []string `json:"urls"`
}

// CloudflareTurnProvider retrieves TURN credentials from the Cloudflare TURN API.
type CloudflareTurnProvider struct {
	client              *http.Client
	endpoint            string
	apiToken            *secrets.SecureString
	requestBody         []byte
	urls                []string
	urlsWithIPPatterns  []string
	hostname            string
	clientCredentialTTL time.Duration
	logger              *slog.Logger
}

// CloudflareTurnProviderConfig holds configuration for creating a CloudflareTurnProvider.
type CloudflareTurnProviderConfig struct {
	APIToken               *secrets.SecureString
	Endpoint               string
	URLs                   []string
	URLsWithIPs            []string
	Hostname               string
	RequestedCredentialTTL time.Duration
	ClientCredentialTTL    time.Duration
	NumHTTPClients         int
	Logger                 *slog.Logger
}

// NewCloudflareTurnProvider creates a new CloudflareTurnProvider.
func NewCloudflareTurnProvider(cfg CloudflareTurnProviderConfig) (*CloudflareTurnProvider, error) {
	reqBody, err := json.Marshal(cloudflareCredentialRequest{
		TTL: int64(cfg.RequestedCredentialTTL.Seconds()),
	})
	if err != nil {
		return nil, &CloudflareRequestError{Cause: err}
	}

	return &CloudflareTurnProvider{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		endpoint:            cfg.Endpoint,
		apiToken:            cfg.APIToken,
		requestBody:         reqBody,
		urls:                cfg.URLs,
		urlsWithIPPatterns:  cfg.URLsWithIPs,
		hostname:            cfg.Hostname,
		clientCredentialTTL: cfg.ClientCredentialTTL,
		logger:              cfg.Logger,
	}, nil
}

// Destroy wipes the API token from protected memory. It should be called when
// the provider is no longer needed.
func (p *CloudflareTurnProvider) Destroy() {
	if p.apiToken != nil {
		p.apiToken.Destroy()
		p.apiToken = nil
	}
}

// RetrieveCredentials fetches TURN credentials from the Cloudflare API, resolves
// the configured hostname to IP addresses, and formats urlsWithIps patterns.
func (p *CloudflareTurnProvider) RetrieveCredentials(ctx context.Context) (*TurnToken, error) {
	// Resolve hostname to IP addresses for urlsWithIps.
	composedURLs, err := p.resolveHostnameURLs(ctx)
	if err != nil {
		return nil, err
	}

	// Make HTTP request to Cloudflare.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, strings.NewReader(string(p.requestBody)))
	if err != nil {
		return nil, &CloudflareRequestError{Cause: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiToken.Plaintext())

	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.WarnContext(ctx, "failed to make http request to Cloudflare Turn", slog.String("error", err.Error()))
		return nil, &CloudflareRequestError{Cause: err}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		p.logger.WarnContext(ctx, "failure requesting credentials from Cloudflare Turn",
			slog.Int("code", resp.StatusCode),
			slog.String("body", string(body)),
		)
		return nil, &CloudflareRequestError{Cause: &httpStatusError{StatusCode: resp.StatusCode}}
	}

	var cfResp cloudflareResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfResp); err != nil {
		return nil, &CloudflareRequestError{Cause: err}
	}

	urls := p.urls
	if urls == nil {
		urls = []string{}
	}

	return &TurnToken{
		Username:    cfResp.IceServers.Username,
		Password:    cfResp.IceServers.Credential,
		TTLSeconds:  int64(p.clientCredentialTTL.Seconds()),
		URLs:        urls,
		URLsWithIPs: composedURLs,
		Hostname:    p.hostname,
	}, nil
}

// resolveHostnameURLs resolves the configured hostname and formats the
// urlsWithIPs patterns with each resolved IP address.
func (p *CloudflareTurnProvider) resolveHostnameURLs(ctx context.Context) ([]string, error) {
	if p.hostname == "" || len(p.urlsWithIPPatterns) == 0 {
		return []string{}, nil
	}

	resolver := net.DefaultResolver
	addrs, err := resolver.LookupIPAddr(ctx, p.hostname)
	if err != nil {
		return nil, &CloudflareDNSError{Hostname: p.hostname, Cause: err}
	}

	var composed []string
	for _, addr := range addrs {
		ipStr := addr.IP.String()
		// Wrap IPv6 addresses in brackets.
		if addr.IP.To4() == nil {
			ipStr = "[" + ipStr + "]"
		}
		for _, pattern := range p.urlsWithIPPatterns {
			composed = append(composed, strings.ReplaceAll(pattern, "%s", ipStr))
		}
	}
	return composed, nil
}

// StaticTurnProvider returns static TURN credentials for development use.
// It does not contact any external service.
type StaticTurnProvider struct {
	URLs     []string
	Hostname string
}

// RetrieveCredentials returns a static TurnToken for development.
func (p *StaticTurnProvider) RetrieveCredentials(ctx context.Context) (*TurnToken, error) {
	urls := p.URLs
	if urls == nil {
		urls = []string{}
	}
	return &TurnToken{
		Username:    "static-turn-user",
		Password:    "static-turn-password",
		TTLSeconds:  86400,
		URLs:        urls,
		URLsWithIPs: []string{},
		Hostname:    p.Hostname,
	}, nil
}

// httpStatusError is an internal error for unexpected HTTP status codes.
type httpStatusError struct {
	StatusCode int
}

func (e *httpStatusError) Error() string {
	return "unexpected status code: " + http.StatusText(e.StatusCode)
}
