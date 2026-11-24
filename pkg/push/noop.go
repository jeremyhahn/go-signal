package push

import "context"

// NoOpProvider discards notifications and reports each as accepted; for development and tests.
type NoOpProvider struct{}

// Send discards the notification and reports it as accepted.
func (NoOpProvider) Send(_ context.Context, _ *PushNotification) (SendPushNotificationResult, error) {
	return SendPushNotificationResult{Accepted: true}, nil
}

// Close is a no-op.
func (NoOpProvider) Close() error {
	return nil
}
