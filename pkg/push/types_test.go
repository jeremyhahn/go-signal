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

func TestPushNotification_Fields(t *testing.T) {
	n := &PushNotification{
		AccountUUID: "uuid-1",
		DeviceID:    1,
		DeviceToken: "token-abc",
		DeviceType:  DeviceTypeAPNs,
		IsUrgent:    true,
		Payload:     []byte{1, 2, 3},
	}
	if n.AccountUUID != "uuid-1" {
		t.Errorf("AccountUUID: got %q, want %q", n.AccountUUID, "uuid-1")
	}
	if n.DeviceType != DeviceTypeAPNs {
		t.Errorf("DeviceType: got %d, want %d", n.DeviceType, DeviceTypeAPNs)
	}
}
