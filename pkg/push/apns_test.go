package push

import "testing"

func TestNewAPNsProvider_Production(t *testing.T) {
	p := NewAPNsProvider(APNsConfig{
		BundleID: "org.signal",
		TeamID:   "TEAM123",
		KeyID:    "KEY456",
	})
	if p.endpoint != apnsProductionEndpoint {
		t.Errorf("endpoint: got %q, want %q", p.endpoint, apnsProductionEndpoint)
	}
	if p.bundleID != "org.signal" {
		t.Errorf("bundleID: got %q, want %q", p.bundleID, "org.signal")
	}
}

func TestNewAPNsProvider_Sandbox(t *testing.T) {
	p := NewAPNsProvider(APNsConfig{
		BundleID: "org.signal",
		Sandbox:  true,
	})
	if p.endpoint != apnsSandboxEndpoint {
		t.Errorf("endpoint: got %q, want %q", p.endpoint, apnsSandboxEndpoint)
	}
}

func TestNewAPNsProvider_DefaultClient(t *testing.T) {
	p := NewAPNsProvider(APNsConfig{})
	if p.client == nil {
		t.Fatal("expected non-nil default client")
	}
}

func TestAPNsProvider_Send(t *testing.T) {
	p := NewAPNsProvider(APNsConfig{})
	err := p.Send(&PushNotification{
		DeviceToken: "test-token",
		DeviceType:  DeviceTypeAPNs,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPNsProvider_Close(t *testing.T) {
	p := NewAPNsProvider(APNsConfig{})
	err := p.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAPNsProvider_ImplementsInterface(t *testing.T) {
	var _ PushProvider = &APNsProvider{}
}
