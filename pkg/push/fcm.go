package push

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// fcmV1EndpointTemplate is the FCM HTTP v1 send endpoint.
	fcmV1EndpointTemplate = "https://fcm.googleapis.com/v1/projects/%s/messages:send"
	// fcmScope is the OAuth2 scope required to call /messages:send.
	fcmScope = "https://www.googleapis.com/auth/firebase.messaging"
	// googleTokenEndpoint is Google's OAuth2 token endpoint.
	// #nosec G101 -- URL constant, not a credential.
	googleTokenEndpoint = "https://oauth2.googleapis.com/token"
	// defaultFCMTimeout is the HTTP client timeout for FCM requests.
	defaultFCMTimeout = 10 * time.Second
	// oauth2JWTAssertionLifetime is how long the assertion JWT is valid.
	// Google caps this at 1h; we use 1h - 5m of slack.
	oauth2JWTAssertionLifetime = 55 * time.Minute
	// accessTokenRefreshSlack is how far ahead of expiry we proactively
	// rotate the cached OAuth2 access token.
	accessTokenRefreshSlack = 60 * time.Second
)

// serviceAccount mirrors the fields of a Google service-account JSON we
// consume. Other fields (client_id, etc.) are ignored.
type serviceAccount struct {
	ProjectID   string `json:"project_id,omitempty"`
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri,omitempty"`
}

// FCMConfig holds the configuration for an FCMProvider.
type FCMConfig struct {
	// ProjectID is the Firebase project ID. Required.
	ProjectID string
	// ServiceAccountJSON is the raw service-account credential bytes.
	// Must contain client_email + private_key (RSA PKCS#1 or PKCS#8 PEM).
	ServiceAccountJSON []byte
	// HTTPClient overrides the default HTTP client. When nil, a client
	// with defaultFCMTimeout is used.
	HTTPClient *http.Client
	// TokenEndpoint overrides googleTokenEndpoint. Tests use this to
	// point at a fake OAuth2 server.
	TokenEndpoint string
	// SendEndpoint overrides the FCM v1 send URL. Tests use this to point
	// at a fake FCM server.
	SendEndpoint string
}

// FCMProvider delivers push notifications via the Firebase Cloud Messaging
// HTTP v1 API. It owns an OAuth2 access-token cache so repeated Send calls
// do not re-mint a token each time.
type FCMProvider struct {
	httpClient *http.Client
	sendURL    string
	tokenURL   string

	clientEmail string
	privateKey  *rsa.PrivateKey

	tokenMu     sync.Mutex
	accessToken string
	tokenExpiry time.Time

	// now is the wall-clock source. Tests override it.
	now func() time.Time
}

// NewFCMProvider parses the service-account JSON, validates the private key,
// and returns a ready-to-use provider. No network calls are made until the
// first Send. ProjectID may be empty when the service-account JSON embeds a
// project_id field.
func NewFCMProvider(cfg FCMConfig) (*FCMProvider, error) {
	var sa serviceAccount
	if err := json.Unmarshal(cfg.ServiceAccountJSON, &sa); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "fcm: parse service account JSON", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("fcm: service account JSON missing client_email or private_key")
	}
	projectID := cfg.ProjectID
	if projectID == "" {
		projectID = sa.ProjectID
	}
	if projectID == "" {
		return nil, errors.New("fcm: ProjectID is required (either via config or service-account JSON)")
	}
	key, err := parseRSAPrivateKey([]byte(sa.PrivateKey))
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "fcm: parse private key", err)
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: defaultFCMTimeout}
	}
	tokenURL := cfg.TokenEndpoint
	if tokenURL == "" {
		tokenURL = sa.TokenURI
	}
	if tokenURL == "" {
		tokenURL = googleTokenEndpoint
	}
	sendURL := cfg.SendEndpoint
	if sendURL == "" {
		sendURL = fmt.Sprintf(fcmV1EndpointTemplate, projectID)
	}
	return &FCMProvider{
		httpClient:  hc,
		sendURL:     sendURL,
		tokenURL:    tokenURL,
		clientEmail: sa.ClientEmail,
		privateKey:  key,
		now:         time.Now,
	}, nil
}

// parseRSAPrivateKey accepts PKCS#1 ("RSA PRIVATE KEY") or PKCS#8
// ("PRIVATE KEY") PEM blocks. Google service-account JSON ships PKCS#8.
func parseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("not a PEM-encoded key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	pkcs8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "parse private key", err)
	}
	key, ok := pkcs8.(*rsa.PrivateKey)
	if !ok {
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("expected RSA key, got %T", pkcs8))
	}
	return key, nil
}

// accessTokenOrFetch returns a cached access token if still valid; otherwise
// it mints a fresh one via the OAuth2 JWT-bearer flow.
func (p *FCMProvider) accessTokenOrFetch(ctx context.Context) (string, error) {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()
	if p.accessToken != "" && p.now().Add(accessTokenRefreshSlack).Before(p.tokenExpiry) {
		return p.accessToken, nil
	}
	tok, exp, err := p.mintAccessToken(ctx)
	if err != nil {
		return "", err
	}
	p.accessToken = tok
	p.tokenExpiry = exp
	return tok, nil
}

// mintAccessToken signs a JWT bearer assertion and POSTs the assertion to
// Google's token endpoint, returning the access_token + computed expiry.
func (p *FCMProvider) mintAccessToken(ctx context.Context) (string, time.Time, error) {
	now := p.now()
	claims := jwt.MapClaims{
		"iss":   p.clientEmail,
		"scope": fcmScope,
		"aud":   p.tokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(oauth2JWTAssertionLifetime).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	assertion, err := tok.SignedString(p.privateKey)
	if err != nil {
		return "", time.Time{}, signalerrors.Wrap(signalerrors.ErrInternal, "fcm: sign JWT", err)
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, signalerrors.Wrap(signalerrors.ErrInternal, "fcm: build token request", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, signalerrors.Wrap(signalerrors.ErrInternal, "fcm: token POST", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, signalerrors.New(signalerrors.ErrUnavailable, "fcm: token endpoint returned "+strconv.Itoa(resp.StatusCode)+": "+string(body))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", time.Time{}, signalerrors.Wrap(signalerrors.ErrInternal, "fcm: decode token response", err)
	}
	if tr.AccessToken == "" {
		return "", time.Time{}, errors.New("fcm: token response missing access_token")
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		// Google guarantees a positive expires_in; treat missing/zero as a
		// short safety window so the next call re-mints.
		ttl = 30 * time.Second
	}
	return tr.AccessToken, p.now().Add(ttl), nil
}

// fcmMessage / fcmRequest mirror the FCM v1 wire shape. Only the fields we
// set today are present; FCM ignores unknown fields, so this is forward-
// compatible.
type fcmRequest struct {
	Message fcmMessage `json:"message"`
}

type fcmMessage struct {
	Token   string            `json:"token"`
	Data    map[string]string `json:"data,omitempty"`
	Android *fcmAndroidConfig `json:"android,omitempty"`
}

type fcmAndroidConfig struct {
	Priority string `json:"priority,omitempty"`
}

// fcmErrorResponse mirrors the v1 error envelope. We only need the inner
// status enum to distinguish UNREGISTERED.
type fcmErrorResponse struct {
	Error struct {
		Code    int    `json:"code"`
		Status  string `json:"status"`
		Message string `json:"message"`
		Details []struct {
			Type      string `json:"@type"`
			ErrorCode string `json:"errorCode"`
		} `json:"details"`
	} `json:"error"`
}

// fcmDataKeyForType mirrors Java FcmSender's switch on NotificationType.
func fcmDataKeyForType(t NotificationType) string {
	switch t {
	case NotificationTypeNotification:
		return "newMessageAlert"
	case NotificationTypeAttemptLogin:
		return "attemptLoginContext"
	case NotificationTypeChallenge:
		return "challenge"
	case NotificationTypeRateLimitChallenge:
		return "rateLimitChallenge"
	default:
		return ""
	}
}

// Send delivers a notification via FCM HTTP v1.
func (p *FCMProvider) Send(ctx context.Context, n *PushNotification) (SendPushNotificationResult, error) {
	if n == nil {
		return SendPushNotificationResult{}, errors.New("fcm: nil notification")
	}
	token, err := p.accessTokenOrFetch(ctx)
	if err != nil {
		return SendPushNotificationResult{}, &SendError{Provider: "fcm", DeviceToken: n.DeviceToken, Cause: err}
	}
	dataKey := fcmDataKeyForType(n.Type)
	if dataKey == "" {
		return SendPushNotificationResult{}, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("fcm: unknown notification type %d", n.Type))
	}
	priority := "NORMAL"
	if n.Urgent {
		priority = "HIGH"
	}
	body, err := json.Marshal(fcmRequest{
		Message: fcmMessage{
			Token:   n.DeviceToken,
			Data:    map[string]string{dataKey: n.Data},
			Android: &fcmAndroidConfig{Priority: priority},
		},
	})
	if err != nil {
		return SendPushNotificationResult{}, signalerrors.Wrap(signalerrors.ErrInternal, "fcm: marshal request", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.sendURL, bytes.NewReader(body))
	if err != nil {
		return SendPushNotificationResult{}, &SendError{Provider: "fcm", DeviceToken: n.DeviceToken, Cause: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return SendPushNotificationResult{}, &SendError{Provider: "fcm", DeviceToken: n.DeviceToken, Cause: err}
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		return SendPushNotificationResult{Accepted: true}, nil
	}
	return interpretFCMError(resp.StatusCode, respBody), nil
}

// interpretFCMError maps an FCM v1 error response onto our typed result.
// UNREGISTERED in any error detail (or status=NOT_FOUND with messaging-
// error code UNREGISTERED) marks the token as invalid.
func interpretFCMError(statusCode int, body []byte) SendPushNotificationResult {
	var er fcmErrorResponse
	_ = json.Unmarshal(body, &er)
	reason := er.Error.Status
	if reason == "" {
		reason = fmt.Sprintf("http%d", statusCode)
	}
	unregistered := false
	for _, d := range er.Error.Details {
		if d.ErrorCode == "UNREGISTERED" {
			unregistered = true
			reason = "UNREGISTERED"
			break
		}
	}
	return SendPushNotificationResult{
		Accepted:        false,
		RejectionReason: reason,
		Unregistered:    unregistered,
	}
}

// Close releases resources held by the FCM provider.
func (p *FCMProvider) Close() error {
	if p.httpClient != nil {
		p.httpClient.CloseIdleConnections()
	}
	return nil
}
