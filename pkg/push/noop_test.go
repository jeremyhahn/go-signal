package push

import (
	"context"
	"testing"
)

func TestNoOpProvider_Send(t *testing.T) {
	p := NoOpProvider{}
	res, err := p.Send(context.Background(), &PushNotification{DeviceToken: "test"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Accepted {
		t.Error("expected NoOpProvider.Send to report Accepted=true")
	}
}

func TestNoOpProvider_SendNil(t *testing.T) {
	p := NoOpProvider{}
	if _, err := p.Send(context.Background(), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNoOpProvider_Close(t *testing.T) {
	p := NoOpProvider{}
	if err := p.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNoOpProvider_ImplementsInterface(t *testing.T) {
	var _ PushProvider = NoOpProvider{}
}
