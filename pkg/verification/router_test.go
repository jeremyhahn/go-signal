package verification

import (
	"context"
	"errors"
	"testing"
)

type recordingTransport struct {
	name string
	sent []string
}

func (r *recordingTransport) Name() string { return r.name }
func (r *recordingTransport) SendCode(_ context.Context, destination, _ string, _ ...SendOption) error {
	r.sent = append(r.sent, destination)
	return nil
}

func TestDestinationChannel(t *testing.T) {
	cases := []struct {
		dest string
		want Channel
	}{
		{"+15551234567", ChannelSMS},
		{"15551234567", ChannelSMS}, // legacy non-E.164 still SMS
		{"user@example.com", ChannelEmail},
		{"", ChannelSMS},
	}
	for _, c := range cases {
		t.Run(c.dest, func(t *testing.T) {
			if got := DestinationChannel(c.dest); got != c.want {
				t.Errorf("DestinationChannel(%q) = %d, want %d", c.dest, got, c.want)
			}
		})
	}
}

func TestRouterTransport_SMSRoute(t *testing.T) {
	sms := &recordingTransport{name: "sms"}
	email := &recordingTransport{name: "email"}
	r := &RouterTransport{SMS: sms, Email: email}
	if err := r.SendCode(context.Background(), "+15551234567", "123456"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	if len(sms.sent) != 1 || sms.sent[0] != "+15551234567" {
		t.Errorf("SMS leg did not receive call: %+v", sms.sent)
	}
	if len(email.sent) != 0 {
		t.Errorf("email leg should be untouched: %+v", email.sent)
	}
}

func TestRouterTransport_EmailRoute(t *testing.T) {
	sms := &recordingTransport{name: "sms"}
	email := &recordingTransport{name: "email"}
	r := &RouterTransport{SMS: sms, Email: email}
	if err := r.SendCode(context.Background(), "user@example.com", "123456"); err != nil {
		t.Fatalf("SendCode: %v", err)
	}
	if len(email.sent) != 1 || email.sent[0] != "user@example.com" {
		t.Errorf("email leg did not receive call: %+v", email.sent)
	}
	if len(sms.sent) != 0 {
		t.Errorf("SMS leg should be untouched: %+v", sms.sent)
	}
}

func TestRouterTransport_MissingChannelErrors(t *testing.T) {
	r := &RouterTransport{SMS: nil, Email: nil}
	err := r.SendCode(context.Background(), "+1555", "x")
	if !errors.Is(err, ErrChannelNotConfigured) {
		t.Errorf("expected ErrChannelNotConfigured, got %v", err)
	}
	err = r.SendCode(context.Background(), "user@example.com", "x")
	if !errors.Is(err, ErrChannelNotConfigured) {
		t.Errorf("expected ErrChannelNotConfigured for email, got %v", err)
	}
}

func TestRouterTransport_Name(t *testing.T) {
	r := &RouterTransport{}
	if r.Name() != "router" {
		t.Errorf("Name = %q, want router", r.Name())
	}
}
