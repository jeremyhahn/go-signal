package push

// SendError indicates a failure to deliver a push notification.
type SendError struct {
	Provider    string
	DeviceToken string
	Cause       error
}

// Error implements the error interface.
func (e *SendError) Error() string {
	return "push/" + e.Provider + ": failed to send to " + e.DeviceToken + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause for errors.As/errors.Is traversal.
func (e *SendError) Unwrap() error {
	return e.Cause
}

// ProviderNotConfiguredError indicates that no provider is configured for the
// requested device type.
type ProviderNotConfiguredError struct {
	DeviceType DeviceType
}

// Error implements the error interface.
func (e *ProviderNotConfiguredError) Error() string {
	switch e.DeviceType {
	case DeviceTypeAPNs:
		return "push: APNs provider not configured"
	case DeviceTypeFCM:
		return "push: FCM provider not configured"
	default:
		return "push: unknown provider not configured"
	}
}

// InvalidTokenError indicates that a device token was rejected by the push
// provider, typically meaning the device has unregistered.
type InvalidTokenError struct {
	Provider    string
	DeviceToken string
}

// Error implements the error interface.
func (e *InvalidTokenError) Error() string {
	return "push/" + e.Provider + ": invalid device token: " + e.DeviceToken
}
