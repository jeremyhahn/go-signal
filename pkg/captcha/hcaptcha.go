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
	// hCaptchaVerifyURL is the endpoint used to verify hCaptcha tokens.
	hCaptchaVerifyURL = "https://api.hcaptcha.com/siteverify"

	// defaultHCaptchaTimeout is the maximum time to wait for the hCaptcha API.
	defaultHCaptchaTimeout = 10 * time.Second
)

// hCaptchaResponse is the JSON payload returned by the hCaptcha siteverify API.
type hCaptchaResponse struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes"`
}

// HCaptchaVerifier implements CaptchaVerifier using the hCaptcha siteverify
// API (https://docs.hcaptcha.com/).
type HCaptchaVerifier struct {
	secretKey        *secrets.SecureString
	endpoint         string
	client           *http.Client
	siteKeysByAction map[Action][]string
}

// HCaptchaConfig holds the configuration for an HCaptchaVerifier.
type HCaptchaConfig struct {
	// SecretKey is the server-side secret associated with the hCaptcha site.
	// Required.
	SecretKey *secrets.SecureString

	// Endpoint overrides the default siteverify URL. Leave empty to use the
	// production hCaptcha endpoint. Primarily useful for testing.
	Endpoint string

	// HTTPClient is the HTTP client used for outbound requests. When nil,
	// a client with a 10 s timeout is used.
	HTTPClient *http.Client

	// SiteKeysByAction is the per-action allowlist of site keys the
	// Checker enforces against incoming submissions. Empty map means
	// "no enforcement" — every site key is accepted. Site keys are
	// compared case-insensitively (lower-cased here at config time).
	SiteKeysByAction map[Action][]string
}

// NewHCaptchaVerifier returns a configured HCaptchaVerifier. It returns
// HCaptchaConfigError if SecretKey is empty.
func NewHCaptchaVerifier(cfg HCaptchaConfig) (*HCaptchaVerifier, error) {
	if cfg.SecretKey == nil || cfg.SecretKey.IsDestroyed() {
		return nil, &HCaptchaConfigError{Message: "secretKey is required"}
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = hCaptchaVerifyURL
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHCaptchaTimeout}
	}

	return &HCaptchaVerifier{
		secretKey:        cfg.SecretKey,
		endpoint:         endpoint,
		client:           client,
		siteKeysByAction: normalizeSiteKeys(cfg.SiteKeysByAction),
	}, nil
}

// ValidSiteKeys returns the lower-cased allowlist for the given action, or
// nil when the verifier was not configured with any restriction (in which
// case the Checker treats all site keys as accepted).
func (v *HCaptchaVerifier) ValidSiteKeys(action Action) []string {
	if v.siteKeysByAction == nil {
		return nil
	}
	return v.siteKeysByAction[action]
}

// normalizeSiteKeys lower-cases every site key so containsKey can compare
// without re-applying the normalization on every Verify call. Returns nil
// when in is nil so the verifier preserves the "no enforcement" mode.
func normalizeSiteKeys(in map[Action][]string) map[Action][]string {
	if in == nil {
		return nil
	}
	out := make(map[Action][]string, len(in))
	for action, keys := range in {
		normalized := make([]string, 0, len(keys))
		for _, k := range keys {
			normalized = append(normalized, normalize(k))
		}
		out[action] = normalized
	}
	return out
}

// Verify sends a POST request to the hCaptcha siteverify endpoint and returns
// the parsed result. A non-nil error indicates a network or parse failure;
// a failed CAPTCHA challenge is reported through VerifyResult.Success == false.
func (v *HCaptchaVerifier) Verify(ctx context.Context, token string, remoteIP string, _ string) (*VerifyResult, error) {
	form := url.Values{}
	form.Set("secret", v.secretKey.Plaintext())
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &CaptchaNetworkError{Provider: "hcaptcha", Cause: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, &CaptchaNetworkError{Provider: "hcaptcha", Cause: err}
	}
	defer resp.Body.Close() //nolint:errcheck

	var parsed hCaptchaResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, &CaptchaParseError{Provider: "hcaptcha", Cause: err}
	}

	return &VerifyResult{
		Success:    parsed.Success,
		Hostname:   parsed.Hostname,
		ErrorCodes: parsed.ErrorCodes,
	}, nil
}
