package push

import "testing"

func TestDeviceType_Constants(t *testing.T) {
	if DeviceTypeAPNs != 0 {
		t.Errorf("DeviceTypeAPNs: got %d, want 0", DeviceTypeAPNs)
	}
	if DeviceTypeFCM != 1 {
		t.Errorf("DeviceTypeFCM: got %d, want 1", DeviceTypeFCM)
	}
}

func TestNotificationType_Constants(t *testing.T) {
	// Pin the iota ordering — downstream code may persist these values.
	cases := []struct {
		got  NotificationType
		want int
	}{
		{NotificationTypeNotification, 0},
		{NotificationTypeAttemptLogin, 1},
		{NotificationTypeChallenge, 2},
		{NotificationTypeRateLimitChallenge, 3},
	}
	for _, c := range cases {
		if int(c.got) != c.want {
			t.Errorf("NotificationType iota drift: got %d, want %d", c.got, c.want)
		}
	}
}

func TestPushNotification_Fields(t *testing.T) {
	n := &PushNotification{
		AccountUUID: "uuid-1",
		DeviceID:    1,
		DeviceToken: "token-abc",
		DeviceType:  DeviceTypeAPNs,
		Type:        NotificationTypeChallenge,
		Urgent:      true,
		Data:        "challenge-token",
	}
	if n.AccountUUID != "uuid-1" {
		t.Errorf("AccountUUID: got %q, want %q", n.AccountUUID, "uuid-1")
	}
	if n.DeviceType != DeviceTypeAPNs {
		t.Errorf("DeviceType: got %d, want %d", n.DeviceType, DeviceTypeAPNs)
	}
	if n.Type != NotificationTypeChallenge {
		t.Errorf("Type: got %d, want %d", n.Type, NotificationTypeChallenge)
	}
	if !n.Urgent {
		t.Error("expected Urgent=true")
	}
	if n.Data != "challenge-token" {
		t.Errorf("Data: got %q, want %q", n.Data, "challenge-token")
	}
}

func TestSendPushNotificationResult_ZeroValueIsRejection(t *testing.T) {
	// A zero-value result must read as "not accepted, not unregistered" so
	// callers that forget to populate it don't accidentally claim success.
	var r SendPushNotificationResult
	if r.Accepted {
		t.Error("zero-value SendPushNotificationResult must not be Accepted")
	}
	if r.Unregistered {
		t.Error("zero-value SendPushNotificationResult must not be Unregistered")
	}
	if r.RejectionReason != "" {
		t.Errorf("RejectionReason: expected empty, got %q", r.RejectionReason)
	}
}
