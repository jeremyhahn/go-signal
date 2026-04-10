package push

// NoOpProvider is a push provider that discards all notifications.
// It is used in development and testing when push delivery is not required.
type NoOpProvider struct{}

// Send discards the notification and returns nil.
func (NoOpProvider) Send(_ *PushNotification) error {
	return nil
}

// Close is a no-op.
func (NoOpProvider) Close() error {
	return nil
}
