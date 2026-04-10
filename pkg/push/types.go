// Package push provides push notification delivery for the Signal server.
// It defines the PushNotification type, the PushProvider interface, and a
// PushManager that routes notifications to the correct provider by device type.
package push

// DeviceType identifies the platform of a device.
type DeviceType int

const (
	// DeviceTypeAPNs represents an Apple Push Notification service device.
	DeviceTypeAPNs DeviceType = iota
	// DeviceTypeFCM represents a Firebase Cloud Messaging device.
	DeviceTypeFCM
)

// PushNotification holds the data required to deliver a push notification
// to a specific device.
type PushNotification struct {
	// AccountUUID is the ACI UUID of the account that owns the device.
	AccountUUID string
	// DeviceID is the Signal device ID.
	DeviceID uint64
	// DeviceToken is the platform-specific push token (APNs device token
	// or FCM registration token).
	DeviceToken string
	// DeviceType identifies the push platform for routing.
	DeviceType DeviceType
	// IsUrgent indicates whether the notification should be delivered
	// immediately (true) or can be deferred (false).
	IsUrgent bool
	// Payload is the opaque notification payload. For Signal, this is
	// typically a zero-length or minimal wakeup payload.
	Payload []byte
}

// PushProvider delivers push notifications to a specific platform.
// Implementations must be safe for concurrent use.
type PushProvider interface {
	// Send delivers a push notification. Returns nil on success.
	Send(notification *PushNotification) error
	// Close releases any resources held by the provider.
	Close() error
}
