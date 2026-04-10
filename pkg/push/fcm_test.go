package push

import "testing"

func TestNewFCMProvider_Config(t *testing.T) {
	p := NewFCMProvider(FCMConfig{ProjectID: "my-project"})
	if p.projectID != "my-project" {
		t.Errorf("projectID: got %q, want %q", p.projectID, "my-project")
	}
}

func TestNewFCMProvider_DefaultClient(t *testing.T) {
	p := NewFCMProvider(FCMConfig{})
	if p.client == nil {
		t.Fatal("expected non-nil default client")
	}
}

func TestFCMProvider_Send(t *testing.T) {
	p := NewFCMProvider(FCMConfig{ProjectID: "my-project"})
	err := p.Send(&PushNotification{
		DeviceToken: "test-token",
		DeviceType:  DeviceTypeFCM,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFCMProvider_Close(t *testing.T) {
	p := NewFCMProvider(FCMConfig{})
	err := p.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFCMProvider_ImplementsInterface(t *testing.T) {
	var _ PushProvider = &FCMProvider{}
}
