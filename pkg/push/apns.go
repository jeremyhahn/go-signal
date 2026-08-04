package push

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	"github.com/sideshow/apns2/token"
)

// APNsConfig holds the configuration for an APNsProvider.
type APNsConfig struct {
	// BundleID is the iOS application bundle identifier (apns-topic).
	BundleID string
	// TeamID is the Apple Developer Team ID.
	TeamID string
	// KeyID is the APNs authentication key ID.
	KeyID string
	// SigningKeyPEM is the PEM-encoded ECDSA (P-256) private key used to
	// sign the JWT auth tokens. Apple issues this when the .p8 key is
	// downloaded from the developer console.
	SigningKeyPEM []byte
	// Sandbox uses the APNs sandbox endpoint when true.
	Sandbox bool
}

// APNsProvider delivers push notifications via the Apple Push Notification
// service HTTP/2 API. It wraps sideshow/apns2 so the provider boundary
// matches the Java APNSender contract: typed NotificationType values map
// to per-type payloads, priorities, and collapse-ids.
type APNsProvider struct {
	client   *apns2.Client
	bundleID string
}

// NewAPNsProvider creates a configured APNsProvider. The SigningKey is
// parsed as an ECDSA P-256 private key (apple's .p8 key format).
func NewAPNsProvider(cfg APNsConfig) (*APNsProvider, error) {
	if cfg.BundleID == "" {
		return nil, errors.New("apns: BundleID is required")
	}
	if cfg.TeamID == "" {
		return nil, errors.New("apns: TeamID is required")
	}
	if cfg.KeyID == "" {
		return nil, errors.New("apns: KeyID is required")
	}
	key, err := parseECDSAPrivateKey(cfg.SigningKeyPEM)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "apns: parse signing key", err)
	}
	tok := &token.Token{AuthKey: key, KeyID: cfg.KeyID, TeamID: cfg.TeamID}
	client := apns2.NewTokenClient(tok)
	if cfg.Sandbox {
		client = client.Development()
	} else {
		client = client.Production()
	}
	return &APNsProvider{client: client, bundleID: cfg.BundleID}, nil
}

// parseECDSAPrivateKey decodes a PEM-wrapped PKCS#8 ECDSA private key. Apple's
// .p8 keys are issued in this format.
func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("empty PEM input")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("not a PEM-encoded key")
	}
	pkcs8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "parse PKCS8", err)
	}
	key, ok := pkcs8.(*ecdsa.PrivateKey)
	if !ok {
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, fmt.Sprintf("expected ECDSA key, got %T", pkcs8))
	}
	return key, nil
}

// apnsCollapseIDForType returns the collapse-id Apple should use to coalesce
// outstanding push notifications. Mirrors Java APNSender: only urgent
// NotificationTypeNotification messages collapse, under "incoming-message".
func apnsCollapseIDForType(n *PushNotification) string {
	if n.Type == NotificationTypeNotification && n.Urgent {
		return "incoming-message"
	}
	return ""
}

// buildAPNsPayloadAndPushType constructs the payload + push-type for a given
// notification. Mirrors Java APNSender.sendNotification's switch.
func buildAPNsPayloadAndPushType(n *PushNotification) (*payload.Payload, apns2.EPushType) {
	switch n.Type {
	case NotificationTypeNotification:
		if n.Urgent {
			// "APN_NSE_NOTIFICATION_PAYLOAD" — mutable-content + a localized
			// alert that the iOS notification service extension expands.
			return payload.NewPayload().MutableContent().AlertLocKey("APN_Message"), apns2.PushTypeAlert
		}
		// "APN_BACKGROUND_PAYLOAD" — silent wakeup.
		return payload.NewPayload().ContentAvailable(), apns2.PushTypeBackground
	case NotificationTypeAttemptLogin:
		return payload.NewPayload().
			MutableContent().
			AlertLocKey("APN_Message").
			Custom("attemptLoginContext", n.Data), apns2.PushTypeAlert
	case NotificationTypeChallenge:
		return payload.NewPayload().
			ContentAvailable().
			Custom("challenge", n.Data), apns2.PushTypeBackground
	case NotificationTypeRateLimitChallenge:
		return payload.NewPayload().
			ContentAvailable().
			Custom("rateLimitChallenge", n.Data), apns2.PushTypeBackground
	default:
		// Unknown type falls back to a silent wakeup so the server never
		// blocks a delivery on a payload-shape lookup mistake.
		return payload.NewPayload().ContentAvailable(), apns2.PushTypeBackground
	}
}

// deliveryPriorityFor mirrors Java: BACKGROUND push-type is always
// CONSERVE_POWER (5); ALERT honors the notification's urgent bit.
func deliveryPriorityFor(pushType apns2.EPushType, urgent bool) int {
	if pushType == apns2.PushTypeBackground {
		return apns2.PriorityLow
	}
	if urgent {
		return apns2.PriorityHigh
	}
	return apns2.PriorityLow
}

// apnsMaxExpiration matches Java APNSender.MAX_EXPIRATION: store-and-forward
// as long as APNs will hold it (~year 2038 from the int-max-seconds heritage).
var apnsMaxExpiration = time.Unix(int64(^uint32(0)>>1), 0)

// Send delivers a push via APNs HTTP/2. The ctx deadline applies to the
// underlying HTTP request through apns2's transport.
func (p *APNsProvider) Send(ctx context.Context, n *PushNotification) (SendPushNotificationResult, error) {
	if n == nil {
		return SendPushNotificationResult{}, errors.New("apns: nil notification")
	}
	pl, pushType := buildAPNsPayloadAndPushType(n)
	note := &apns2.Notification{
		DeviceToken: n.DeviceToken,
		Topic:       p.bundleID,
		Payload:     pl,
		Priority:    deliveryPriorityFor(pushType, n.Urgent),
		PushType:    pushType,
		Expiration:  apnsMaxExpiration,
		CollapseID:  apnsCollapseIDForType(n),
	}
	resp, err := p.client.PushWithContext(ctx, note)
	if err != nil {
		return SendPushNotificationResult{}, &SendError{Provider: "apns", DeviceToken: n.DeviceToken, Cause: err}
	}
	return interpretAPNsResponse(resp), nil
}

// interpretAPNsResponse maps an apns2.Response to our typed result. The
// Unregistered flag mirrors Java's logic (Unregistered / BadDeviceToken /
// ExpiredToken).
func interpretAPNsResponse(resp *apns2.Response) SendPushNotificationResult {
	if resp.Sent() {
		return SendPushNotificationResult{Accepted: true}
	}
	result := SendPushNotificationResult{
		Accepted:        false,
		RejectionReason: resp.Reason,
	}
	switch resp.Reason {
	case apns2.ReasonUnregistered, apns2.ReasonBadDeviceToken, apns2.ReasonExpiredToken:
		result.Unregistered = true
	}
	if !resp.Timestamp.IsZero() {
		ts := resp.Timestamp.Time
		result.TokenInvalidationTimestamp = &ts
	}
	return result
}

// Close releases resources held by the APNs provider.
func (p *APNsProvider) Close() error {
	// apns2.Client has no Close; it relies on the embedded http.Client's
	// idle-connection sweeper. Surface a Close anyway so the manager
	// interface stays uniform.
	if p.client != nil && p.client.HTTPClient != nil {
		p.client.HTTPClient.CloseIdleConnections()
	}
	return nil
}
