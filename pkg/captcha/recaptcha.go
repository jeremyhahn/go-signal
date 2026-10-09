package captcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

const (
	// reCAPTCHAVerifyURL is the endpoint used to verify reCAPTCHA tokens.
	reCAPTCHAVerifyURL = "https://www.google.com/recaptcha/api/siteverify"

	// defaultReCAPTCHATimeout is the maximum time to wait for the reCAPTCHA API.
	defaultReCAPTCHATimeout = 10 * time.Second
)

// reCAPTCHAResponse is the JSON payload returned by the reCAPTCHA siteverify API.
// The Score and Action fields are populated only for reCAPTCHA v3 tokens.
type reCAPTCHAResponse struct {
	Success     bool     `json:"success"`
	Score       float64  `json:"score"`
	Action      string   `json:"action"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// ReCAPTCHAVerifier implements CaptchaVerifier using the Google reCAPTCHA
// siteverify API. It supports both v2 (checkbox/invisible) and v3 (score-based)
// tokens; the response Score and Action fields are populated for v3 only.
type ReCAPTCHAVerifier struct {
	secretKey        *secrets.SecureString
	endpoint         string
	client           *http.Client
	siteKeysByAction map[Action][]string
}

// ReCAPTCHAConfig holds the configuration for a ReCAPTCHAVerifier.
type ReCAPTCHAConfig struct {
	// SecretKey is the server-side secret associated with the reCAPTCHA site.
	// Required.
	SecretKey *secrets.SecureString

	// Endpoint overrides the default siteverify URL. Leave empty to use the
	// production Google endpoint. Primarily useful for testing.
	Endpoint string

	// HTTPClient is the HTTP client used for outbound requests. When nil,
	// a client with a 10 s timeout is used.
	HTTPClient *http.Client

	// SiteKeysByAction is the per-action allowlist of site keys the
	// Checker enforces. nil = no restriction.
	SiteKeysByAction map[Action][]string
}

// NewReCAPTCHAVerifier returns a configured ReCAPTCHAVerifier. It returns
// ReCAPTCHAConfigError if SecretKey is empty.
func NewReCAPTCHAVerifier(ctx context.Context, cfg ReCAPTCHAConfig) (*ReCAPTCHAVerifier, error) {
	if cfg.SecretKey == nil || cfg.SecretKey.IsDestroyed(ctx) {
		return nil, &ReCAPTCHAConfigError{Message: "secretKey is required"}
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = reCAPTCHAVerifyURL
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultReCAPTCHATimeout}
	}

	return &ReCAPTCHAVerifier{
		secretKey:        cfg.SecretKey,
		endpoint:         endpoint,
		client:           client,
		siteKeysByAction: normalizeSiteKeys(cfg.SiteKeysByAction),
	}, nil
}

// ValidSiteKeys returns the lower-cased allowlist for the given action, or
// nil when no restriction is configured.
func (v *ReCAPTCHAVerifier) ValidSiteKeys(action Action) []string {
	if v.siteKeysByAction == nil {
		return nil
	}
	return v.siteKeysByAction[action]
}

// Verify sends a POST request to the reCAPTCHA siteverify endpoint and returns
// the parsed result. A non-nil error indicates a network or parse failure;
// a failed CAPTCHA challenge is reported through VerifyResult.Success == false.
// For v3 tokens, VerifyResult.Score and VerifyResult.Action are populated.
func (v *ReCAPTCHAVerifier) Verify(ctx context.Context, token string, remoteIP string, _ string) (*VerifyResult, error) {
	form := url.Values{}
	form.Set("secret", v.secretKey.Plaintext(ctx))
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &CaptchaNetworkError{Provider: "recaptcha", Cause: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, &CaptchaNetworkError{Provider: "recaptcha", Cause: err}
	}
	defer resp.Body.Close() //nolint:errcheck

	var parsed reCAPTCHAResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, &CaptchaParseError{Provider: "recaptcha", Cause: err}
	}

	return &VerifyResult{
		Success:    parsed.Success,
		Score:      parsed.Score,
		Action:     parsed.Action,
		Hostname:   parsed.Hostname,
		ErrorCodes: parsed.ErrorCodes,
	}, nil
}
