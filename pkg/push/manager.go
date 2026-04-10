package push

import (
	"log/slog"
)

// PushManager routes push notifications to the correct provider based on
// device type. It is safe for concurrent use.
type PushManager struct {
	providers map[DeviceType]PushProvider
	logger    *slog.Logger
}

// PushManagerConfig holds the configuration for a PushManager.
type PushManagerConfig struct {
	// APNs is the provider for Apple devices. When nil, NoOpProvider is used.
	APNs PushProvider
	// FCM is the provider for Android devices. When nil, NoOpProvider is used.
	FCM PushProvider
	// Logger is used for debug and error output.
	Logger *slog.Logger
}

// NewPushManager creates a PushManager that routes to the appropriate provider.
func NewPushManager(cfg PushManagerConfig) *PushManager {
	apns := cfg.APNs
	if apns == nil {
		apns = NoOpProvider{}
	}
	fcm := cfg.FCM
	if fcm == nil {
		fcm = NoOpProvider{}
	}
	return &PushManager{
		providers: map[DeviceType]PushProvider{
			DeviceTypeAPNs: apns,
			DeviceTypeFCM:  fcm,
		},
		logger: cfg.Logger,
	}
}

// Send delivers a push notification by routing to the correct provider
// based on the notification's DeviceType.
func (m *PushManager) Send(notification *PushNotification) error {
	if notification == nil {
		return nil
	}

	provider, ok := m.providers[notification.DeviceType]
	if !ok {
		return &ProviderNotConfiguredError{DeviceType: notification.DeviceType}
	}

	if err := provider.Send(notification); err != nil {
		m.logger.Error("push notification failed",
			slog.String("account", notification.AccountUUID),
			slog.Uint64("device", notification.DeviceID),
			slog.String("error", err.Error()))
		return err
	}

	m.logger.Debug("push notification sent",
		slog.String("account", notification.AccountUUID),
		slog.Uint64("device", notification.DeviceID))

	return nil
}

// Close shuts down all configured providers.
func (m *PushManager) Close() error {
	var firstErr error
	for _, p := range m.providers {
		if err := p.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
