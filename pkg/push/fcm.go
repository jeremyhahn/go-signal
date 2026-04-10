package push

import (
	"net/http"
	"time"
)

const (
	// fcmV1Endpoint is the FCM HTTP v1 API endpoint template.
	fcmV1Endpoint = "https://fcm.googleapis.com/v1/projects/"
	// defaultFCMTimeout is the HTTP client timeout for FCM requests.
	defaultFCMTimeout = 10 * time.Second
)

// FCMProvider delivers push notifications via the Firebase Cloud Messaging
// HTTP v1 API.
type FCMProvider struct {
	client    *http.Client
	projectID string
	endpoint  string
}

// FCMConfig holds the configuration for an FCMProvider.
type FCMConfig struct {
	// ProjectID is the Firebase project ID.
	ProjectID string
	// HTTPClient overrides the default HTTP client. When nil, a client
	// with defaultFCMTimeout is used.
	HTTPClient *http.Client
}

// NewFCMProvider creates a configured FCMProvider.
func NewFCMProvider(cfg FCMConfig) *FCMProvider {
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultFCMTimeout}
	}

	return &FCMProvider{
		client:    client,
		projectID: cfg.ProjectID,
		endpoint:  fcmV1Endpoint + cfg.ProjectID + "/messages:send",
	}
}

// Send delivers a push notification via the FCM HTTP v1 API.
func (p *FCMProvider) Send(_ *PushNotification) error {
	// TODO: Implement full FCM HTTP v1 request with OAuth2 authentication.
	// The production implementation will:
	// 1. Obtain an OAuth2 access token from service account credentials
	// 2. POST to {fcmV1Endpoint}{projectID}/messages:send
	// 3. Build the FCM message with data payload
	// 4. Parse the response for error codes (UNREGISTERED, etc.)

	return nil
}

// Close releases resources held by the FCM provider.
func (p *FCMProvider) Close() error {
	p.client.CloseIdleConnections()
	return nil
}
