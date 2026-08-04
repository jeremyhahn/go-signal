// Package push provides push notification delivery for the Signal server.
// Mirrors the Java APNSender + FcmSender contract: typed NotificationType
// values map to per-platform payloads, and Send returns a structured
// SendPushNotificationResult so callers can route invalid-token responses
// back to account cleanup.
package push

import (
	"context"
	"time"
)

// DeviceType identifies the platform of a device.
type DeviceType int

const (
	// DeviceTypeAPNs represents an Apple Push Notification service device.
	DeviceTypeAPNs DeviceType = iota
	// DeviceTypeFCM represents a Firebase Cloud Messaging device.
	DeviceTypeFCM
)

// NotificationType mirrors Java PushNotification.NotificationType. Each
// value drives a distinct payload shape and priority on both APNs and FCM
// transports — see apns.go and fcm.go for the per-type mapping.
type NotificationType int

const (
	// NotificationTypeNotification is the standard "new message available"
	// wakeup. Urgency controls APNs push-type (ALERT vs BACKGROUND) and
	// FCM AndroidConfig priority (HIGH vs NORMAL).
	NotificationTypeNotification NotificationType = iota
	// NotificationTypeAttemptLogin signals a high-priority device-linking
	// attempt; APNs uses an alert payload with attemptLoginContext, FCM
	// puts the same data under the attemptLoginContext key.
	NotificationTypeAttemptLogin
	// NotificationTypeChallenge wakes a device to solve a challenge —
	// silent (content-available / NORMAL) with a `challenge` data field.
	NotificationTypeChallenge
	// NotificationTypeRateLimitChallenge is the rate-limit variant of
	// Challenge, carried under `rateLimitChallenge`.
	NotificationTypeRateLimitChallenge
)

// PushNotification is the platform-agnostic request to deliver one push.
type PushNotification struct {
	// AccountUUID is the ACI UUID of the account that owns the device.
	// Included for logs and downstream callbacks; not transmitted in the
	// payload (server preserves recipient privacy).
	AccountUUID string
	// DeviceID is the Signal device ID.
	DeviceID uint64
	// DeviceToken is the platform-specific push token (APNs device token
	// or FCM registration token).
	DeviceToken string
	// DeviceType selects the provider.
	DeviceType DeviceType
	// Type controls the payload shape and priority. See NotificationType.
	Type NotificationType
	// Urgent escalates a NotificationTypeNotification from a silent
	// background wakeup to a user-visible alert. Ignored for Challenge /
	// RateLimitChallenge / AttemptLogin (those have fixed priority).
	Urgent bool
	// Data is the per-Type custom string (e.g. the challenge token,
	// attempt-login context). Empty when the Type does not carry data.
	Data string
}

// SendPushNotificationResult mirrors Java SendPushNotificationResult: it
// distinguishes (a) accepted/rejected, (b) the provider's rejection
// reason, (c) whether the token has been invalidated so callers can
// clean up the account record, and (d) when the invalidation became
// effective (APNs reports this in `timestamp`).
type SendPushNotificationResult struct {
	Accepted                   bool
	RejectionReason            string
	Unregistered               bool
	TokenInvalidationTimestamp *time.Time
}

// PushProvider delivers push notifications to a specific platform.
// Implementations must be safe for concurrent use.
type PushProvider interface {
	Send(ctx context.Context, notification *PushNotification) (SendPushNotificationResult, error)
	Close() error
}
