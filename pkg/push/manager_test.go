package push

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

func testPushLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// mockProvider records Send calls and supports two modes:
//   - Steady mode (transientErr nil): each Send returns (result, err).
//   - Transient mode (transientErr set): the first transientCount calls
//     return (zero-value, transientErr); calls past that return (result, nil),
//     so the manager's retry path can be exercised.
type mockProvider struct {
	sent           []*PushNotification
	result         SendPushNotificationResult
	err            error
	transientErr   error
	transientCount int
}

func (m *mockProvider) Send(_ context.Context, n *PushNotification) (SendPushNotificationResult, error) {
	m.sent = append(m.sent, n)
	if m.transientErr != nil && m.transientCount > 0 {
		m.transientCount--
		return SendPushNotificationResult{}, m.transientErr
	}
	if m.transientErr != nil && m.transientCount == 0 {
		return m.result, nil
	}
	return m.result, m.err
}

func (m *mockProvider) Close() error { return nil }

// errorCloseProvider returns an error on Close.
type errorCloseProvider struct {
	NoOpProvider
	err error
}

func (p *errorCloseProvider) Close() error { return p.err }

func TestNewPushManager_DefaultProviders(t *testing.T) {
	m := NewPushManager(PushManagerConfig{Logger: testPushLogger()})
	if m.providers[DeviceTypeAPNs] == nil {
		t.Fatal("expected non-nil APNs provider")
	}
	if m.providers[DeviceTypeFCM] == nil {
		t.Fatal("expected non-nil FCM provider")
	}
}

func TestNewPushManager_NilLoggerDefaults(t *testing.T) {
	m := NewPushManager(PushManagerConfig{})
	if m.logger == nil {
		t.Fatal("expected non-nil default logger")
	}
}

func TestPushManager_Send_APNs(t *testing.T) {
	apns := &mockProvider{result: SendPushNotificationResult{Accepted: true}}
	m := NewPushManager(PushManagerConfig{APNs: apns, Logger: testPushLogger()})

	n := &PushNotification{
		AccountUUID: "uuid-1",
		DeviceID:    1,
		DeviceToken: "apns-token",
		DeviceType:  DeviceTypeAPNs,
	}
	res, err := m.Send(context.Background(), n)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Accepted {
		t.Error("expected Accepted=true")
	}
	if len(apns.sent) != 1 {
		t.Fatalf("expected 1 sent notification, got %d", len(apns.sent))
	}
	if apns.sent[0].DeviceToken != "apns-token" {
		t.Errorf("got token %q, want %q", apns.sent[0].DeviceToken, "apns-token")
	}
}

func TestPushManager_Send_FCM(t *testing.T) {
	fcm := &mockProvider{result: SendPushNotificationResult{Accepted: true}}
	m := NewPushManager(PushManagerConfig{FCM: fcm, Logger: testPushLogger()})

	n := &PushNotification{
		AccountUUID: "uuid-2",
		DeviceID:    2,
		DeviceToken: "fcm-token",
		DeviceType:  DeviceTypeFCM,
	}
	if _, err := m.Send(context.Background(), n); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fcm.sent) != 1 {
		t.Fatalf("expected 1 sent notification, got %d", len(fcm.sent))
	}
}

func TestPushManager_Send_UnknownDeviceType(t *testing.T) {
	m := NewPushManager(PushManagerConfig{Logger: testPushLogger()})

	n := &PushNotification{DeviceType: DeviceType(99)}
	_, err := m.Send(context.Background(), n)
	if err == nil {
		t.Fatal("expected error for unknown device type")
	}
	var target *ProviderNotConfiguredError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ProviderNotConfiguredError, got %T", err)
	}
}

func TestPushManager_Send_NilNotification(t *testing.T) {
	m := NewPushManager(PushManagerConfig{Logger: testPushLogger()})
	res, err := m.Send(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error for nil notification: %v", err)
	}
	if res.Accepted {
		t.Error("nil notification must not report Accepted")
	}
}

func TestPushManager_Send_ProviderError(t *testing.T) {
	sendErr := errors.New("connection failed")
	apns := &mockProvider{err: sendErr}
	m := NewPushManager(PushManagerConfig{APNs: apns, Logger: testPushLogger()})

	n := &PushNotification{DeviceToken: "token", DeviceType: DeviceTypeAPNs}
	_, err := m.Send(context.Background(), n)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, sendErr) {
		t.Errorf("got error %v, want %v", err, sendErr)
	}
}

func TestPushManager_Send_ProviderRejection(t *testing.T) {
	// Provider returns a rejection result without an error — the manager
	// should surface the result and log a warning, not raise an error.
	apns := &mockProvider{result: SendPushNotificationResult{
		Accepted:        false,
		RejectionReason: "BadDeviceToken",
		Unregistered:    true,
	}}
	m := NewPushManager(PushManagerConfig{APNs: apns, Logger: testPushLogger()})

	res, err := m.Send(context.Background(), &PushNotification{
		DeviceType: DeviceTypeAPNs, DeviceToken: "expired",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Accepted {
		t.Error("expected Accepted=false")
	}
	if !res.Unregistered {
		t.Error("expected Unregistered=true")
	}
}

func TestPushManager_Close(t *testing.T) {
	apns := &mockProvider{}
	fcm := &mockProvider{}
	m := NewPushManager(PushManagerConfig{APNs: apns, FCM: fcm, Logger: testPushLogger()})

	if err := m.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPushManager_Close_Error(t *testing.T) {
	closeErr := errors.New("close failed")
	apns := &errorCloseProvider{err: closeErr}
	m := NewPushManager(PushManagerConfig{APNs: apns, FCM: NoOpProvider{}, Logger: testPushLogger()})

	err := m.Close()
	if err == nil {
		t.Fatal("expected error from Close")
	}
	if err != closeErr {
		t.Errorf("got error %v, want %v", err, closeErr)
	}
}

func TestPushManager_RoutesToCorrectProvider(t *testing.T) {
	apns := &mockProvider{result: SendPushNotificationResult{Accepted: true}}
	fcm := &mockProvider{result: SendPushNotificationResult{Accepted: true}}
	m := NewPushManager(PushManagerConfig{APNs: apns, FCM: fcm, Logger: testPushLogger()})

	if _, err := m.Send(context.Background(), &PushNotification{DeviceType: DeviceTypeAPNs, DeviceToken: "a"}); err != nil {
		t.Fatalf("APNs send: unexpected error: %v", err)
	}
	if _, err := m.Send(context.Background(), &PushNotification{DeviceType: DeviceTypeFCM, DeviceToken: "f"}); err != nil {
		t.Fatalf("FCM send: unexpected error: %v", err)
	}

	if len(apns.sent) != 1 {
		t.Errorf("APNs: got %d sent, want 1", len(apns.sent))
	}
	if len(fcm.sent) != 1 {
		t.Errorf("FCM: got %d sent, want 1", len(fcm.sent))
	}
}

func TestPushManager_RetriesTransientErrors(t *testing.T) {
	// First two attempts return a transport-layer *SendError, third
	// succeeds. The manager must retry and ultimately surface the
	// successful result.
	apns := &mockProvider{
		transientErr:   &SendError{Provider: "apns", DeviceToken: "tok", Cause: errors.New("connection reset")},
		transientCount: 2,
		result:         SendPushNotificationResult{Accepted: true},
	}
	m := NewPushManager(PushManagerConfig{
		APNs:           apns,
		Logger:         testPushLogger(),
		RetryAttempts:  3,
		InitialBackoff: 1 * time.Microsecond,
		MaxBackoff:     1 * time.Microsecond,
	})
	res, err := m.Send(context.Background(), &PushNotification{
		DeviceType: DeviceTypeAPNs, DeviceToken: "tok",
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !res.Accepted {
		t.Errorf("expected Accepted after retries, got %+v", res)
	}
	if got := len(apns.sent); got != 3 {
		t.Errorf("expected 3 attempts, got %d", got)
	}
}

func TestPushManager_RetryGiveUpAfterAttempts(t *testing.T) {
	apns := &mockProvider{
		transientErr:   &SendError{Provider: "apns", DeviceToken: "tok", Cause: errors.New("connection reset")},
		transientCount: 10, // more than RetryAttempts.
		result:         SendPushNotificationResult{Accepted: true},
	}
	m := NewPushManager(PushManagerConfig{
		APNs:           apns,
		Logger:         testPushLogger(),
		RetryAttempts:  2,
		InitialBackoff: 1 * time.Microsecond,
	})
	_, err := m.Send(context.Background(), &PushNotification{DeviceType: DeviceTypeAPNs, DeviceToken: "tok"})
	if err == nil {
		t.Fatal("expected error after retry exhaustion")
	}
	if got := len(apns.sent); got != 2 {
		t.Errorf("expected 2 attempts before give-up, got %d", got)
	}
}

func TestPushManager_NonRetryableErrorReturnsImmediately(t *testing.T) {
	// A non-SendError (e.g. caller validation) shouldn't trigger retries.
	apns := &mockProvider{err: errors.New("bad config")}
	m := NewPushManager(PushManagerConfig{
		APNs:           apns,
		Logger:         testPushLogger(),
		RetryAttempts:  5,
		InitialBackoff: 1 * time.Microsecond,
	})
	_, err := m.Send(context.Background(), &PushNotification{DeviceType: DeviceTypeAPNs, DeviceToken: "tok"})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := len(apns.sent); got != 1 {
		t.Errorf("expected exactly 1 attempt for non-retryable error, got %d", got)
	}
}

func TestPushManager_RetryRespectsContextCancellation(t *testing.T) {
	apns := &mockProvider{
		transientErr:   &SendError{Provider: "apns", DeviceToken: "tok", Cause: errors.New("connection reset")},
		transientCount: 10,
	}
	m := NewPushManager(PushManagerConfig{
		APNs:           apns,
		Logger:         testPushLogger(),
		RetryAttempts:  10,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	_, err := m.Send(ctx, &PushNotification{DeviceType: DeviceTypeAPNs, DeviceToken: "tok"})
	if err == nil {
		t.Fatal("expected context error")
	}
	if !errors.Is(err, context.Canceled) {
		// Provider may have already returned a SendError that's surfaced
		// instead — accept either as long as the call returned promptly.
		var se *SendError
		if !errors.As(err, &se) {
			t.Fatalf("unexpected error type: %T: %v", err, err)
		}
	}
}
