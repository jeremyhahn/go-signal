package push

import "testing"

func TestNoOpProvider_Send(t *testing.T) {
	p := NoOpProvider{}
	err := p.Send(&PushNotification{DeviceToken: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNoOpProvider_SendNil(t *testing.T) {
	p := NoOpProvider{}
	err := p.Send(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNoOpProvider_Close(t *testing.T) {
	p := NoOpProvider{}
	err := p.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNoOpProvider_ImplementsInterface(t *testing.T) {
	var _ PushProvider = NoOpProvider{}
}
