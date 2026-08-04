package push

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// defaultRetryAttempts is the default number of attempts (including the
// first) Send makes against a provider before giving up.
const defaultRetryAttempts = 3

// defaultInitialBackoff is the wait time before the first retry. Subsequent
// retries double this delay, capped at defaultMaxBackoff.
const defaultInitialBackoff = 200 * time.Millisecond

// defaultMaxBackoff caps the exponential backoff so a deep slow-down
// doesn't stretch a single Send past 10s of total wall time.
const defaultMaxBackoff = 2 * time.Second

// PushManager routes push notifications to the correct provider based on
// device type. It is safe for concurrent use.
type PushManager struct {
	providers      map[DeviceType]PushProvider
	logger         *slog.Logger
	retryAttempts  int
	initialBackoff time.Duration
	maxBackoff     time.Duration
}

// PushManagerConfig holds the configuration for a PushManager.
type PushManagerConfig struct {
	// APNs is the provider for Apple devices. When nil, NoOpProvider is used.
	APNs PushProvider
	// FCM is the provider for Android devices. When nil, NoOpProvider is used.
	FCM PushProvider
	// Logger is used for debug and error output.
	Logger *slog.Logger

	// RetryAttempts caps the total number of provider invocations per Send
	// (including the first). Zero uses defaultRetryAttempts. Set to 1 to
	// disable retries entirely.
	RetryAttempts int
	// InitialBackoff is the wait time before the first retry; subsequent
	// retries double until MaxBackoff. Zero uses defaultInitialBackoff.
	InitialBackoff time.Duration
	// MaxBackoff caps the exponential backoff. Zero uses defaultMaxBackoff.
	MaxBackoff time.Duration
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
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	attempts := cfg.RetryAttempts
	if attempts <= 0 {
		attempts = defaultRetryAttempts
	}
	initial := cfg.InitialBackoff
	if initial <= 0 {
		initial = defaultInitialBackoff
	}
	maxBackoff := cfg.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = defaultMaxBackoff
	}
	return &PushManager{
		providers: map[DeviceType]PushProvider{
			DeviceTypeAPNs: apns,
			DeviceTypeFCM:  fcm,
		},
		logger:         logger,
		retryAttempts:  attempts,
		initialBackoff: initial,
		maxBackoff:     maxBackoff,
	}
}

// Send delivers a push notification by routing to the correct provider
// based on the notification's DeviceType. Transient transport errors
// (anything wrapped in *SendError where ctx is still valid) are retried
// with exponential backoff up to RetryAttempts. Application-level
// rejections (Accepted=false with an Unregistered/permanent reason) are
// returned immediately — retrying them would just hammer the upstream.
func (m *PushManager) Send(ctx context.Context, notification *PushNotification) (SendPushNotificationResult, error) {
	if notification == nil {
		return SendPushNotificationResult{}, nil
	}

	provider, ok := m.providers[notification.DeviceType]
	if !ok {
		return SendPushNotificationResult{}, &ProviderNotConfiguredError{DeviceType: notification.DeviceType}
	}

	backoff := m.initialBackoff
	var (
		result SendPushNotificationResult
		err    error
	)
	for attempt := 1; attempt <= m.retryAttempts; attempt++ {
		result, err = provider.Send(ctx, notification)
		if err == nil {
			break
		}
		if !shouldRetryPushError(err) || attempt == m.retryAttempts {
			m.logger.Error("push notification failed",
				slog.String("account", notification.AccountUUID),
				slog.Uint64("device", notification.DeviceID),
				slog.Int("attempt", attempt),
				slog.String("error", err.Error()))
			return result, err
		}
		m.logger.Warn("push notification transient failure; retrying",
			slog.String("account", notification.AccountUUID),
			slog.Uint64("device", notification.DeviceID),
			slog.Int("attempt", attempt),
			slog.Duration("backoff", backoff),
			slog.String("error", err.Error()))
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < m.maxBackoff {
			backoff *= 2
			if backoff > m.maxBackoff {
				backoff = m.maxBackoff
			}
		}
	}

	if !result.Accepted {
		m.logger.Warn("push notification rejected",
			slog.String("account", notification.AccountUUID),
			slog.Uint64("device", notification.DeviceID),
			slog.String("reason", result.RejectionReason),
			slog.Bool("unregistered", result.Unregistered))
		return result, nil
	}

	m.logger.Debug("push notification sent",
		slog.String("account", notification.AccountUUID),
		slog.Uint64("device", notification.DeviceID))
	return result, nil
}

// shouldRetryPushError returns true when err looks like a transient transport
// failure worth retrying. Only *SendError (transport-layer wrapper) is
// retried; configuration/validation errors are surfaced immediately so the
// caller can fix them rather than burn attempts.
func shouldRetryPushError(err error) bool {
	var se *SendError
	return errors.As(err, &se)
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
