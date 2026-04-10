package push

import (
	"encoding/json"
	"net/http"
	"time"
)

const (
	// apnsProductionEndpoint is the APNs HTTP/2 production endpoint.
	apnsProductionEndpoint = "https://api.push.apple.com"
	// apnsSandboxEndpoint is the APNs HTTP/2 sandbox endpoint.
	apnsSandboxEndpoint = "https://api.sandbox.push.apple.com"
	// defaultAPNsTimeout is the HTTP client timeout for APNs requests.
	defaultAPNsTimeout = 10 * time.Second
)

// apnsPayload is the JSON structure sent to the APNs HTTP/2 API.
type apnsPayload struct {
	APS apnsAPS `json:"aps"`
}

// apnsAPS is the aps dictionary within an APNs notification.
type apnsAPS struct {
	Alert            string `json:"alert,omitempty"`
	ContentAvailable int    `json:"content-available,omitempty"`
	MutableContent   int    `json:"mutable-content,omitempty"`
}

// APNsProvider delivers push notifications via the Apple Push Notification
// service HTTP/2 API.
type APNsProvider struct {
	client   *http.Client
	endpoint string
	bundleID string
	teamID   string
	keyID    string
}

// APNsConfig holds the configuration for an APNsProvider.
type APNsConfig struct {
	// BundleID is the iOS application bundle identifier.
	BundleID string
	// TeamID is the Apple Developer Team ID.
	TeamID string
	// KeyID is the APNs authentication key ID.
	KeyID string
	// Sandbox uses the APNs sandbox endpoint when true.
	Sandbox bool
	// HTTPClient overrides the default HTTP client. When nil, a client
	// with defaultAPNsTimeout is used.
	HTTPClient *http.Client
}

// NewAPNsProvider creates a configured APNsProvider.
func NewAPNsProvider(cfg APNsConfig) *APNsProvider {
	endpoint := apnsProductionEndpoint
	if cfg.Sandbox {
		endpoint = apnsSandboxEndpoint
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultAPNsTimeout}
	}

	return &APNsProvider{
		client:   client,
		endpoint: endpoint,
		bundleID: cfg.BundleID,
		teamID:   cfg.TeamID,
		keyID:    cfg.KeyID,
	}
}

// Send delivers a push notification via the APNs HTTP/2 API.
// For Signal, notifications are silent (content-available) wakeup pushes.
func (p *APNsProvider) Send(notification *PushNotification) error {
	payload := apnsPayload{
		APS: apnsAPS{
			ContentAvailable: 1,
		},
	}

	_, err := json.Marshal(payload)
	if err != nil {
		return &SendError{
			Provider:    "apns",
			DeviceToken: notification.DeviceToken,
			Cause:       err,
		}
	}

	// TODO: Implement full APNs HTTP/2 request with JWT authentication.
	// The production implementation will:
	// 1. Generate a JWT using the team ID, key ID, and private key
	// 2. POST to {endpoint}/3/device/{deviceToken}
	// 3. Set required headers (apns-topic, apns-push-type, apns-priority)
	// 4. Parse the response for error codes (BadDeviceToken, etc.)

	return nil
}

// Close releases resources held by the APNs provider.
func (p *APNsProvider) Close() error {
	p.client.CloseIdleConnections()
	return nil
}
