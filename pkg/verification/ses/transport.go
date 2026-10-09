// Package ses implements verification.VerificationTransport backed by the
// AWS SES v2 SendEmail API. The transport hand-rolls AWS Signature V4 so
// the binary does not pull in the full aws-sdk-go-v2 transitive footprint.
//
// One outbound email per code; SES handles deliverability. The body is a
// minimal plaintext template; deployments that need branded HTML mail
// should fork this transport and supply their own template.
//
// Mirrors Java's SES sender path used by Signal-Server's email-based
// verification flow.
package ses

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

const (
	// defaultHTTPTimeout caps the outbound SES request.
	defaultHTTPTimeout = 10 * time.Second
	// sesService is the AWS service tag used by SigV4.
	sesService = "ses"
)

// Config configures an SES email transport.
type Config struct {
	// Region is the AWS region — e.g. "us-east-1". Required.
	Region string
	// AccessKeyID is the AWS access key. Required.
	AccessKeyID string
	// SecretAccessKey is the AWS secret key. Required.
	SecretAccessKey *secrets.SecureString
	// SessionToken is an optional STS session token. When non-empty it
	// is forwarded as X-Amz-Security-Token.
	SessionToken string
	// FromAddress is the verified SES sender. Required.
	FromAddress string
	// Subject overrides the default email subject. Defaults to
	// "Signal verification code".
	Subject string
	// Endpoint overrides https://email.{region}.amazonaws.com — used by
	// tests. Empty selects the region-derived production endpoint.
	Endpoint string
	// HTTPClient overrides the default 10s-timeout client.
	HTTPClient *http.Client
}

// Transport is the verification.VerificationTransport implementation.
type Transport struct {
	client      *http.Client
	endpoint    string
	fromAddress string
	subject     string
	signer      *sigV4
}

var _ verification.VerificationTransport = (*Transport)(nil)

// NewTransport validates the configuration and returns a ready-to-use
// Transport. Fails fast on missing required fields so deployments never
// silently fall through to a no-op when SES is misconfigured.
func NewTransport(ctx context.Context, cfg Config) (*Transport, error) {
	if cfg.Region == "" {
		return nil, errors.New("ses: Region is required")
	}
	if cfg.AccessKeyID == "" {
		return nil, errors.New("ses: AccessKeyID is required")
	}
	if cfg.SecretAccessKey == nil || cfg.SecretAccessKey.Plaintext(ctx) == "" {
		return nil, errors.New("ses: SecretAccessKey is required")
	}
	if cfg.FromAddress == "" {
		return nil, errors.New("ses: FromAddress is required")
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://email." + cfg.Region + ".amazonaws.com"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: defaultHTTPTimeout}
	}
	subject := cfg.Subject
	if subject == "" {
		subject = "Signal verification code"
	}
	return &Transport{
		client:      hc,
		endpoint:    endpoint,
		fromAddress: cfg.FromAddress,
		subject:     subject,
		signer: &sigV4{
			accessKeyID:     cfg.AccessKeyID,
			secretAccessKey: cfg.SecretAccessKey.Plaintext(ctx),
			sessionToken:    cfg.SessionToken,
			region:          cfg.Region,
			service:         sesService,
		},
	}, nil
}

// Name returns the transport identifier.
func (t *Transport) Name() string { return "ses" }

// sesSendRequest is the SES v2 SendEmail JSON body. Only the fields we
// populate are present; SES ignores unknown fields, so this is
// forward-compatible.
type sesSendRequest struct {
	FromEmailAddress string          `json:"FromEmailAddress"`
	Destination      sesDestination  `json:"Destination"`
	Content          sesEmailContent `json:"Content"`
}

type sesDestination struct {
	ToAddresses []string `json:"ToAddresses"`
}

type sesEmailContent struct {
	Simple sesSimpleMessage `json:"Simple"`
}

type sesSimpleMessage struct {
	Subject sesTextBody `json:"Subject"`
	Body    sesBody     `json:"Body"`
}

type sesBody struct {
	Text sesTextBody `json:"Text"`
}

type sesTextBody struct {
	Data    string `json:"Data"`
	Charset string `json:"Charset"`
}

// SendCode delivers a verification code to destination (an RFC 5321 email
// address). Carrier and other SendOption values are ignored — SES does
// not consume them.
func (t *Transport) SendCode(ctx context.Context, destination, code string, _ ...verification.SendOption) error {
	if destination == "" {
		return t.wrapErr(destination, errors.New("destination required"))
	}
	body, err := json.Marshal(sesSendRequest{
		FromEmailAddress: t.fromAddress,
		Destination:      sesDestination{ToAddresses: []string{destination}},
		Content: sesEmailContent{
			Simple: sesSimpleMessage{
				Subject: sesTextBody{Data: t.subject, Charset: "UTF-8"},
				Body: sesBody{
					Text: sesTextBody{
						Data:    "Your Signal verification code is: " + code,
						Charset: "UTF-8",
					},
				},
			},
		},
	})
	if err != nil {
		return t.wrapErr(destination, err)
	}
	endpoint := t.endpoint + "/v2/email/outbound-emails"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return t.wrapErr(destination, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := t.signer.Sign(req, body); err != nil {
		return t.wrapErr(destination, err)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return t.wrapErr(destination, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return t.wrapErr(destination, parseSESError(resp.StatusCode, respBody))
}

// sesErrorEnvelope captures the JSON error shape returned by SES v2 on
// failure. Multiple shapes exist depending on the failure mode; the
// Type/Message pair is the common denominator.
type sesErrorEnvelope struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

// parseSESError decodes the SES error envelope and returns a typed APIError.
func parseSESError(status int, body []byte) error {
	var env sesErrorEnvelope
	if json.Unmarshal(body, &env) == nil && (env.Type != "" || env.Message != "") {
		return &APIError{HTTPStatus: status, Code: env.Type, Message: env.Message}
	}
	return &APIError{HTTPStatus: status, Message: strings.TrimSpace(string(body))}
}

// wrapErr converts an underlying error into a verification.TransportError
// so handlers see a typed chain regardless of which sub-layer failed.
func (t *Transport) wrapErr(destination string, cause error) error {
	return &verification.TransportError{
		Transport:   t.Name(),
		Destination: destination,
		Cause:       cause,
	}
}

// APIError captures an error returned by SES. Code is the SES error
// type (e.g. "MessageRejected"); Message is the human description.
type APIError struct {
	HTTPStatus int
	Code       string
	Message    string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("ses: http %d code=%s: %s", e.HTTPStatus, e.Code, e.Message)
	}
	return fmt.Sprintf("ses: http %d: %s", e.HTTPStatus, e.Message)
}
