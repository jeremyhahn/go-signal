package calling

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// newTestAPIToken creates a SecureString for the given token string in tests.
// The caller is responsible for calling Destroy when done with the provider.
func newTestAPIToken(token string) *secrets.SecureString {
	return secrets.NewSecureString(token)
}

func TestStaticTurnProvider_RetrieveCredentials(t *testing.T) {
	p := &StaticTurnProvider{
		URLs:     []string{"turn:a.com", "turns:b.com"},
		Hostname: "turn.example.com",
	}

	token, err := p.RetrieveCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.Username != "static-turn-user" {
		t.Errorf("got username %q, want %q", token.Username, "static-turn-user")
	}
	if token.TTLSeconds != 86400 {
		t.Errorf("got TTL %d, want 86400", token.TTLSeconds)
	}
	if len(token.URLs) != 2 {
		t.Errorf("got %d URLs, want 2", len(token.URLs))
	}
	if token.Hostname != "turn.example.com" {
		t.Errorf("got hostname %q, want %q", token.Hostname, "turn.example.com")
	}
}

func TestStaticTurnProvider_NilURLs(t *testing.T) {
	p := &StaticTurnProvider{}
	token, err := p.RetrieveCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.URLs == nil {
		t.Error("expected non-nil URLs slice")
	}
	if len(token.URLs) != 0 {
		t.Errorf("expected empty URLs, got %v", token.URLs)
	}
}

func TestNewCloudflareTurnProvider_Success(t *testing.T) {
	apiToken := newTestAPIToken("test-token")
	defer apiToken.Destroy()

	p, err := NewCloudflareTurnProvider(CloudflareTurnProviderConfig{
		APIToken:               apiToken,
		Endpoint:               "https://example.com/api",
		URLs:                   []string{"turn:a.com"},
		URLsWithIPs:            []string{"turn:%s:3478"},
		Hostname:               "turn.example.com",
		RequestedCredentialTTL: 86400 * time.Second,
		ClientCredentialTTL:    43200 * time.Second,
		NumHTTPClients:         2,
		Logger:                 testLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
		return
	}
	if p.endpoint != "https://example.com/api" {
		t.Errorf("got endpoint %q", p.endpoint)
	}
	if p.apiToken == nil || p.apiToken.Plaintext() != "test-token" {
		t.Errorf("got apiToken %v", p.apiToken)
	}
}

func TestCloudflareTurnProvider_RetrieveCredentials_Success(t *testing.T) {
	cfResp := cloudflareResponse{
		IceServers: cloudflareIceServer{
			Username:   "cf-user",
			Credential: "cf-pass",
			URLs:       []string{"turn:cf.com"},
		},
	}
	body, _ := json.Marshal(cfResp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Bearer auth, got %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected JSON content type, got %q", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	p, err := NewCloudflareTurnProvider(CloudflareTurnProviderConfig{
		APIToken:               newTestAPIToken("test-token"),
		Endpoint:               srv.URL,
		URLs:                   []string{"turn:a.com"},
		RequestedCredentialTTL: 3600 * time.Second,
		ClientCredentialTTL:    1800 * time.Second,
		Logger:                 testLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error creating provider: %v", err)
	}

	token, err := p.RetrieveCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.Username != "cf-user" {
		t.Errorf("got username %q, want %q", token.Username, "cf-user")
	}
	if token.Password != "cf-pass" {
		t.Errorf("got password %q, want %q", token.Password, "cf-pass")
	}
	if token.TTLSeconds != 1800 {
		t.Errorf("got TTL %d, want 1800", token.TTLSeconds)
	}
}

func TestCloudflareTurnProvider_RetrieveCredentials_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("server error"))
	}))
	defer srv.Close()

	p, _ := NewCloudflareTurnProvider(CloudflareTurnProviderConfig{
		APIToken:               newTestAPIToken("test-token"),
		Endpoint:               srv.URL,
		RequestedCredentialTTL: 3600 * time.Second,
		ClientCredentialTTL:    1800 * time.Second,
		Logger:                 testLogger(),
	})

	_, err := p.RetrieveCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error for non-201 status")
	}
	var target *CloudflareRequestError
	if !errors.As(err, &target) {
		t.Fatalf("expected *CloudflareRequestError, got %T", err)
	}
}

func TestCloudflareTurnProvider_RetrieveCredentials_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	p, _ := NewCloudflareTurnProvider(CloudflareTurnProviderConfig{
		APIToken:               newTestAPIToken("test-token"),
		Endpoint:               srv.URL,
		RequestedCredentialTTL: 3600 * time.Second,
		ClientCredentialTTL:    1800 * time.Second,
		Logger:                 testLogger(),
	})

	_, err := p.RetrieveCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestCloudflareTurnProvider_ResolveHostnameURLs_EmptyHostname(t *testing.T) {
	p := &CloudflareTurnProvider{
		hostname:           "",
		urlsWithIPPatterns: []string{"turn:%s:3478"},
		logger:             testLogger(),
	}
	urls, err := p.resolveHostnameURLs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected empty URLs, got %v", urls)
	}
}

func TestCloudflareTurnProvider_ResolveHostnameURLs_EmptyPatterns(t *testing.T) {
	p := &CloudflareTurnProvider{
		hostname:           "example.com",
		urlsWithIPPatterns: nil,
		logger:             testLogger(),
	}
	urls, err := p.resolveHostnameURLs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected empty URLs, got %v", urls)
	}
}

func TestCloudflareTurnProvider_ResolveHostnameURLs_ResolvableHostname(t *testing.T) {
	p := &CloudflareTurnProvider{
		hostname:           "localhost",
		urlsWithIPPatterns: []string{"turn:%s:3478"},
		logger:             testLogger(),
	}
	urls, err := p.resolveHostnameURLs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) == 0 {
		t.Error("expected at least one resolved URL for localhost")
	}
}

func TestCloudflareTurnProvider_ResolveHostnameURLs_MultiplePatterns(t *testing.T) {
	p := &CloudflareTurnProvider{
		hostname:           "localhost",
		urlsWithIPPatterns: []string{"turn:%s:3478", "turns:%s:5349"},
		logger:             testLogger(),
	}
	urls, err := p.resolveHostnameURLs(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// localhost resolves to at least 1 IP, with 2 patterns => at least 2 URLs.
	if len(urls) < 2 {
		t.Errorf("expected at least 2 resolved URLs, got %d: %v", len(urls), urls)
	}
}

func TestCloudflareTurnProvider_ResolveHostnameURLs_UnresolvableHostname(t *testing.T) {
	p := &CloudflareTurnProvider{
		hostname:           "this-hostname-does-not-exist-abc123.invalid",
		urlsWithIPPatterns: []string{"turn:%s:3478"},
		logger:             testLogger(),
	}
	_, err := p.resolveHostnameURLs(context.Background())
	if err == nil {
		t.Fatal("expected error for unresolvable hostname")
	}
	var dnsErr *CloudflareDNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("expected CloudflareDNSError, got %T", err)
	}
	if dnsErr.Hostname != "this-hostname-does-not-exist-abc123.invalid" {
		t.Errorf("got hostname %q in error", dnsErr.Hostname)
	}
}

func TestCloudflareTurnProvider_RetrieveCredentials_NilURLsBecomesEmpty(t *testing.T) {
	cfResp := cloudflareResponse{
		IceServers: cloudflareIceServer{
			Username:   "u",
			Credential: "p",
		},
	}
	body, _ := json.Marshal(cfResp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	p, _ := NewCloudflareTurnProvider(CloudflareTurnProviderConfig{
		APIToken:               newTestAPIToken("tok"),
		Endpoint:               srv.URL,
		RequestedCredentialTTL: 60 * time.Second,
		ClientCredentialTTL:    60 * time.Second,
		Logger:                 testLogger(),
	})

	token, err := p.RetrieveCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.URLs == nil {
		t.Error("expected non-nil URLs slice when provider URLs is nil")
	}
	if len(token.URLs) != 0 {
		t.Errorf("expected empty URLs, got %v", token.URLs)
	}
}

func TestCloudflareTurnProvider_RetrieveCredentials_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	p, _ := NewCloudflareTurnProvider(CloudflareTurnProviderConfig{
		APIToken:               newTestAPIToken("tok"),
		Endpoint:               srv.URL,
		RequestedCredentialTTL: 60 * time.Second,
		ClientCredentialTTL:    60 * time.Second,
		Logger:                 testLogger(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.RetrieveCredentials(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestCloudflareTurnProvider_RetrieveCredentials_UnreachableEndpoint(t *testing.T) {
	p := &CloudflareTurnProvider{
		client:      &http.Client{Timeout: time.Second},
		endpoint:    "http://192.0.2.1:1/invalid",
		apiToken:    newTestAPIToken("tok"),
		requestBody: []byte(`{"ttl":60}`),
		logger:      testLogger(),
	}

	_, err := p.RetrieveCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error for unreachable endpoint")
	}
	var cfErr *CloudflareRequestError
	if !errors.As(err, &cfErr) {
		t.Fatalf("expected CloudflareRequestError, got %T", err)
	}
}

func TestCloudflareTurnProvider_RetrieveCredentials_WithHostname(t *testing.T) {
	cfResp := cloudflareResponse{
		IceServers: cloudflareIceServer{
			Username:   "u",
			Credential: "p",
		},
	}
	body, _ := json.Marshal(cfResp)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	p := &CloudflareTurnProvider{
		client:              srv.Client(),
		endpoint:            srv.URL,
		apiToken:            newTestAPIToken("tok"),
		requestBody:         []byte(`{"ttl":60}`),
		urls:                []string{"turn:a.com"},
		urlsWithIPPatterns:  []string{"turn:%s:3478"},
		hostname:            "localhost",
		clientCredentialTTL: 60 * time.Second,
		logger:              testLogger(),
	}

	token, err := p.RetrieveCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(token.URLsWithIPs) == 0 {
		t.Error("expected URLsWithIPs to be populated from hostname resolution")
	}
	if token.Hostname != "localhost" {
		t.Errorf("got hostname %q, want %q", token.Hostname, "localhost")
	}
}

func TestCloudflareTurnProvider_RetrieveCredentials_DNSFailure(t *testing.T) {
	p := &CloudflareTurnProvider{
		client:              &http.Client{Timeout: time.Second},
		endpoint:            "http://localhost:1",
		apiToken:            newTestAPIToken("tok"),
		requestBody:         []byte(`{"ttl":60}`),
		urlsWithIPPatterns:  []string{"turn:%s:3478"},
		hostname:            "this-hostname-does-not-exist-abc123.invalid",
		clientCredentialTTL: 60 * time.Second,
		logger:              testLogger(),
	}

	_, err := p.RetrieveCredentials(context.Background())
	if err == nil {
		t.Fatal("expected DNS error")
	}
	var dnsErr *CloudflareDNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("expected CloudflareDNSError, got %T", err)
	}
}

func TestNewCloudflareTurnProvider_MarshalsRequestBody(t *testing.T) {
	p, err := NewCloudflareTurnProvider(CloudflareTurnProviderConfig{
		RequestedCredentialTTL: 600 * time.Second,
		Logger:                 testLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var req cloudflareCredentialRequest
	if err := json.Unmarshal(p.requestBody, &req); err != nil {
		t.Fatalf("failed to unmarshal request body: %v", err)
	}
	if req.TTL != 600 {
		t.Errorf("got TTL %d, want 600", req.TTL)
	}
}

func TestNewCloudflareTurnProvider_DefaultHTTPClientTimeout(t *testing.T) {
	p, err := NewCloudflareTurnProvider(CloudflareTurnProviderConfig{
		Logger: testLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.client == nil {
		t.Fatal("expected non-nil HTTP client")
	}
	if p.client.Timeout != 10*time.Second {
		t.Errorf("got timeout %v, want 10s", p.client.Timeout)
	}
}

func TestStaticTurnProvider_RetrieveCredentials_EmptyURLsWithIPs(t *testing.T) {
	p := &StaticTurnProvider{URLs: []string{"turn:a.com"}}
	token, err := p.RetrieveCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(token.URLsWithIPs) != 0 {
		t.Errorf("expected empty URLsWithIPs, got %v", token.URLsWithIPs)
	}
}

func TestStaticTurnProvider_RetrieveCredentials_WithHostname(t *testing.T) {
	p := &StaticTurnProvider{Hostname: "custom.example.com"}
	token, err := p.RetrieveCredentials(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token.Hostname != "custom.example.com" {
		t.Errorf("got hostname %q, want %q", token.Hostname, "custom.example.com")
	}
}

func TestStaticTurnProvider_ImplementsTurnCredentialProvider(t *testing.T) {
	var _ TurnCredentialProvider = (*StaticTurnProvider)(nil)
}

func TestCloudflareTurnProvider_ImplementsTurnCredentialProvider(t *testing.T) {
	var _ TurnCredentialProvider = (*CloudflareTurnProvider)(nil)
}

func TestCloudflareTurnProvider_Destroy(t *testing.T) {
	tok := newTestAPIToken("destroy-me")
	p := &CloudflareTurnProvider{
		apiToken: tok,
		logger:   testLogger(),
	}
	p.Destroy()
	if p.apiToken != nil {
		t.Error("expected apiToken to be nil after Destroy")
	}
}

func TestCloudflareTurnProvider_Destroy_Idempotent(t *testing.T) {
	tok := newTestAPIToken("idempotent")
	p := &CloudflareTurnProvider{
		apiToken: tok,
		logger:   testLogger(),
	}
	p.Destroy()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("second Destroy panicked: %v", r)
		}
	}()
	p.Destroy()
}

func TestHttpStatusError(t *testing.T) {
	e := &httpStatusError{StatusCode: 500}
	if e.Error() != "unexpected status code: Internal Server Error" {
		t.Errorf("got error %q", e.Error())
	}
}

func TestHttpStatusError_NotFound(t *testing.T) {
	e := &httpStatusError{StatusCode: 404}
	if e.Error() != "unexpected status code: Not Found" {
		t.Errorf("got error %q", e.Error())
	}
}

func TestHttpStatusError_Forbidden(t *testing.T) {
	e := &httpStatusError{StatusCode: 403}
	expected := "unexpected status code: Forbidden"
	if e.Error() != expected {
		t.Errorf("got %q, want %q", e.Error(), expected)
	}
}
