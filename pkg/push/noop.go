package push

import "context"

// NoOpProvider is a push provider that discards all notifications.
// It is used in development and testing when push delivery is not required.
// Every Send is treated as an accepted delivery so callers can exercise
// the provider boundary without a live transport.
type NoOpProvider struct{}

// Send discards the notification and reports it as accepted.
func (NoOpProvider) Send(_ context.Context, _ *PushNotification) (SendPushNotificationResult, error) {
	return SendPushNotificationResult{Accepted: true}, nil
}

// Close is a no-op.
func (NoOpProvider) Close() error {
	return nil
}
