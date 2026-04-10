package push

import (
	"errors"
	"log/slog"
	"testing"
)

func testPushLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// mockProvider records Send calls and can return configured errors.
type mockProvider struct {
	sent []*PushNotification
	err  error
}

func (m *mockProvider) Send(n *PushNotification) error {
	m.sent = append(m.sent, n)
	return m.err
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

func TestPushManager_Send_APNs(t *testing.T) {
	apns := &mockProvider{}
	m := NewPushManager(PushManagerConfig{APNs: apns, Logger: testPushLogger()})

	n := &PushNotification{
		AccountUUID: "uuid-1",
		DeviceID:    1,
		DeviceToken: "apns-token",
		DeviceType:  DeviceTypeAPNs,
	}
	if err := m.Send(n); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(apns.sent) != 1 {
		t.Fatalf("expected 1 sent notification, got %d", len(apns.sent))
	}
	if apns.sent[0].DeviceToken != "apns-token" {
		t.Errorf("got token %q, want %q", apns.sent[0].DeviceToken, "apns-token")
	}
}

func TestPushManager_Send_FCM(t *testing.T) {
	fcm := &mockProvider{}
	m := NewPushManager(PushManagerConfig{FCM: fcm, Logger: testPushLogger()})

	n := &PushNotification{
		AccountUUID: "uuid-2",
		DeviceID:    2,
		DeviceToken: "fcm-token",
		DeviceType:  DeviceTypeFCM,
	}
	if err := m.Send(n); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fcm.sent) != 1 {
		t.Fatalf("expected 1 sent notification, got %d", len(fcm.sent))
	}
}

func TestPushManager_Send_UnknownDeviceType(t *testing.T) {
	m := NewPushManager(PushManagerConfig{Logger: testPushLogger()})

	n := &PushNotification{
		DeviceType: DeviceType(99),
	}
	err := m.Send(n)
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
	if err := m.Send(nil); err != nil {
		t.Fatalf("unexpected error for nil notification: %v", err)
	}
}

func TestPushManager_Send_ProviderError(t *testing.T) {
	sendErr := errors.New("connection failed")
	apns := &mockProvider{err: sendErr}
	m := NewPushManager(PushManagerConfig{APNs: apns, Logger: testPushLogger()})

	n := &PushNotification{
		DeviceToken: "token",
		DeviceType:  DeviceTypeAPNs,
	}
	err := m.Send(n)
	if err == nil {
		t.Fatal("expected error")
	}
	if err != sendErr {
		t.Errorf("got error %v, want %v", err, sendErr)
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
	// Use a manager with only APNs configured so iteration is over a single
	// erroring provider; the FCM slot remains NoOpProvider (no error).
	apns := &errorCloseProvider{err: closeErr}
	// Replace the FCM slot with a NoOpProvider that succeeds, ensuring the
	// first error encountered is always the APNs close error.
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
	apns := &mockProvider{}
	fcm := &mockProvider{}
	m := NewPushManager(PushManagerConfig{APNs: apns, FCM: fcm, Logger: testPushLogger()})

	// Send to APNs
	if err := m.Send(&PushNotification{DeviceType: DeviceTypeAPNs, DeviceToken: "a"}); err != nil {
		t.Fatalf("APNs send: unexpected error: %v", err)
	}
	// Send to FCM
	if err := m.Send(&PushNotification{DeviceType: DeviceTypeFCM, DeviceToken: "f"}); err != nil {
		t.Fatalf("FCM send: unexpected error: %v", err)
	}

	if len(apns.sent) != 1 {
		t.Errorf("APNs: got %d sent, want 1", len(apns.sent))
	}
	if len(fcm.sent) != 1 {
		t.Errorf("FCM: got %d sent, want 1", len(fcm.sent))
	}
}
