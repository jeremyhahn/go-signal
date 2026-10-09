// Package twilio implements a verification.Transport backed by the Twilio
// Verify REST API. The server hosts a Verify Service in its Twilio account;
// each SendCode call POSTs to that service's /Verifications endpoint with the
// destination phone number. Twilio owns the code generation, delivery, and
// expiry — our local Manager treats Twilio Verify as an opaque transport and
// validates the user-supplied code through Twilio's /VerificationCheck
// endpoint via the Verify method.
//
// Mirrors Java's TwilioVerifySender: minimum surface for a production SMS
// transport with zero exposure of internal code material.
package twilio

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

const (
	defaultBaseURL    = "https://verify.twilio.com/v2"
	defaultHTTPTimout = 10 * time.Second
)

// Config configures a Twilio Verify Transport.
type Config struct {
	// AccountSID is the Twilio account SID (used as HTTP Basic username).
	AccountSID string
	// AuthToken is the Twilio auth token (used as HTTP Basic password).
	AuthToken *secrets.SecureString
	// ServiceSID is the Verify Service SID under the Twilio account.
	ServiceSID string
	// Channel selects the delivery channel: "sms", "call", or "whatsapp".
	// Empty defaults to "sms".
	Channel string
	// BaseURL overrides https://verify.twilio.com/v2 (for tests).
	BaseURL string
	// HTTPClient overrides the default HTTP client.
	HTTPClient *http.Client
}

// Transport is the verification.Transport implementation backed by Twilio
// Verify. Send calls Twilio's create-Verification endpoint; the supplied
// `code` argument is ignored because Twilio Verify generates the code itself
// and never accepts a server-side override (this is the security guarantee
// Twilio Verify provides over raw SMS APIs).
type Transport struct {
	client     *http.Client
	baseURL    string
	accountSID string
	authToken  *secrets.SecureString
	serviceSID string
	channel    string
}

var _ verification.VerificationTransport = (*Transport)(nil)

// NewTransport returns a configured Twilio Verify Transport. Fails fast when
// AccountSID / AuthToken / ServiceSID are missing so deployments don't
// silently fall through to a no-op.
func NewTransport(cfg Config) (*Transport, error) {
	if cfg.AccountSID == "" {
		return nil, errors.New("twilio: AccountSID is required")
	}
	if cfg.AuthToken == nil || cfg.AuthToken.IsEmpty() {
		return nil, errors.New("twilio: AuthToken is required")
	}
	if cfg.ServiceSID == "" {
		return nil, errors.New("twilio: ServiceSID is required")
	}
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: defaultHTTPTimout}
	}
	channel := cfg.Channel
	if channel == "" {
		channel = "sms"
	}
	return &Transport{
		client:     hc,
		baseURL:    baseURL,
		accountSID: cfg.AccountSID,
		authToken:  cfg.AuthToken,
		serviceSID: cfg.ServiceSID,
		channel:    channel,
	}, nil
}

// Name returns the transport identifier.
// authorize sets HTTP Basic credentials on req. The auth token stays sealed
// on the Transport and is revealed only here, for this one request; an
// unavailable token fails the call rather than sending an empty password.
func (t *Transport) authorize(req *http.Request) error {
	token, err := t.authToken.Reveal()
	if err != nil {
		return err
	}
	req.SetBasicAuth(t.accountSID, token)
	return nil
}

func (t *Transport) Name() string { return "twilio" }

// SendCode triggers a Twilio Verify SMS to the destination. The code
// argument is ignored — Twilio generates and sends its own code, which the
// caller later validates via Verify(). Returns a verification.TransportError
// wrapping the underlying failure on transport or API errors.
func (t *Transport) SendCode(ctx context.Context, destination string, _ string, opts ...verification.SendOption) error {
	_ = verification.ApplySendOptions(opts...) // Twilio Verify ignores carrier.
	form := url.Values{
		"To":      {destination},
		"Channel": {t.channel},
	}
	endpoint := fmt.Sprintf("%s/Services/%s/Verifications", t.baseURL, t.serviceSID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return t.wrapErr(destination, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := t.authorize(req); err != nil {
		return t.wrapErr(destination, err)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return t.wrapErr(destination, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return t.wrapErr(destination, parseTwilioError(resp.StatusCode, body))
}

// Verify checks a user-submitted code against Twilio's stored verification.
// Returns (true, nil) when Twilio reports status=approved; (false, nil) when
// the code is pending or rejected (caller surfaces InvalidCodeError);
// non-nil error only on transport/API failure.
func (t *Transport) Verify(ctx context.Context, destination, code string) (bool, error) {
	form := url.Values{
		"To":   {destination},
		"Code": {code},
	}
	endpoint := fmt.Sprintf("%s/Services/%s/VerificationCheck", t.baseURL, t.serviceSID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, t.wrapErr(destination, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := t.authorize(req); err != nil {
		return false, t.wrapErr(destination, err)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return false, t.wrapErr(destination, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		var r struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return false, t.wrapErr(destination, signalerrors.Wrap(signalerrors.ErrInternal, "decode response", err))
		}
		return r.Status == "approved", nil
	}
	// 404 means the verification ran out or was never created; treat as
	// failed verification rather than an error so the caller can return
	// InvalidCodeError.
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, t.wrapErr(destination, parseTwilioError(resp.StatusCode, body))
}

// parseTwilioError attempts to decode the Twilio JSON error envelope and
// returns a typed error preserving the API error code.
func parseTwilioError(status int, body []byte) error {
	var er struct {
		Code     int    `json:"code"`
		Message  string `json:"message"`
		MoreInfo string `json:"more_info"`
		Status   int    `json:"status"`
	}
	if json.Unmarshal(body, &er) == nil && er.Message != "" {
		return &APIError{HTTPStatus: status, Code: er.Code, Message: er.Message}
	}
	return &APIError{HTTPStatus: status, Message: strings.TrimSpace(string(body))}
}

// wrapErr is the common terminator that converts an underlying error into a
// verification.TransportError so handlers can keep the typed-error chain.
func (t *Transport) wrapErr(destination string, cause error) error {
	return &verification.TransportError{
		Transport:   t.Name(),
		Destination: destination,
		Cause:       cause,
	}
}

// APIError captures an error reported by Twilio. Code mirrors the Twilio
// numeric error code (e.g. 60200 = Invalid parameter).
type APIError struct {
	HTTPStatus int
	Code       int
	Message    string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("twilio: http %d code=%d: %s", e.HTTPStatus, e.Code, e.Message)
	}
	return fmt.Sprintf("twilio: http %d: %s", e.HTTPStatus, e.Message)
}
