package main

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/push"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
)

// seedAccountWithTokens builds an in-memory account+device pair carrying
// both APNs and FCM registration IDs so each clearStaleDeviceToken test
// case starts from a known good baseline.
func seedAccountWithTokens(t *testing.T) (*accounts.AccountsManager, string, uint64) {
	t.Helper()
	store := memory.NewMemoryAccountStore()
	mgr := accounts.NewAccountsManager(store, 6)
	acct := &accounts.Account{
		UUID:        "11111111-1111-1111-1111-111111111111",
		Number:      "+15550009999",
		IdentityKey: []byte("idk"),
		Devices: []accounts.Device{
			{
				ID:                    accounts.PrimaryDeviceID,
				AuthToken:             "t",
				ApnRegistrationID:     "apn-token",
				VoipApnRegistrationID: "voip-apn",
				GcmRegistrationID:     "gcm-token",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID: 1, PublicKey: []byte("pk"), Signature: []byte("sig"),
				},
			},
		},
	}
	if err := mgr.Create(context.Background(), acct); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return mgr, acct.UUID, accounts.PrimaryDeviceID
}

func TestClearStaleDeviceToken_APNs(t *testing.T) {
	mgr, uuid, deviceID := seedAccountWithTokens(t)
	if err := clearStaleDeviceToken(context.Background(), mgr, uuid, deviceID, push.DeviceTypeAPNs); err != nil {
		t.Fatalf("clearStaleDeviceToken: %v", err)
	}
	got, _ := mgr.Get(context.Background(), uuid)
	dev := got.GetDevice(deviceID)
	if dev == nil {
		t.Fatal("device disappeared")
	}
	if dev.ApnRegistrationID != "" {
		t.Errorf("ApnRegistrationID = %q, want empty", dev.ApnRegistrationID)
	}
	if dev.VoipApnRegistrationID != "" {
		t.Errorf("VoipApnRegistrationID = %q, want empty", dev.VoipApnRegistrationID)
	}
	// FCM token must remain untouched — the unregistration was reported by APNs.
	if dev.GcmRegistrationID != "gcm-token" {
		t.Errorf("GcmRegistrationID = %q, expected unchanged", dev.GcmRegistrationID)
	}
}

func TestClearStaleDeviceToken_FCM(t *testing.T) {
	mgr, uuid, deviceID := seedAccountWithTokens(t)
	if err := clearStaleDeviceToken(context.Background(), mgr, uuid, deviceID, push.DeviceTypeFCM); err != nil {
		t.Fatalf("clearStaleDeviceToken: %v", err)
	}
	got, _ := mgr.Get(context.Background(), uuid)
	dev := got.GetDevice(deviceID)
	if dev == nil {
		t.Fatal("device disappeared")
	}
	if dev.GcmRegistrationID != "" {
		t.Errorf("GcmRegistrationID = %q, want empty", dev.GcmRegistrationID)
	}
	// APNs token must remain intact.
	if dev.ApnRegistrationID != "apn-token" {
		t.Errorf("ApnRegistrationID = %q, expected unchanged", dev.ApnRegistrationID)
	}
}

func TestClearStaleDeviceToken_NoOpWhenTokenAlreadyCleared(t *testing.T) {
	mgr, uuid, deviceID := seedAccountWithTokens(t)
	// First call clears.
	if err := clearStaleDeviceToken(context.Background(), mgr, uuid, deviceID, push.DeviceTypeAPNs); err != nil {
		t.Fatalf("first clearStaleDeviceToken: %v", err)
	}
	// Second call must be a no-op (no Update returned).
	if err := clearStaleDeviceToken(context.Background(), mgr, uuid, deviceID, push.DeviceTypeAPNs); err != nil {
		t.Fatalf("second clearStaleDeviceToken: %v", err)
	}
}

func TestClearStaleDeviceToken_AccountNotFound(t *testing.T) {
	mgr, _, deviceID := seedAccountWithTokens(t)
	err := clearStaleDeviceToken(context.Background(), mgr, "ffffffff-ffff-ffff-ffff-ffffffffffff", deviceID, push.DeviceTypeAPNs)
	if err == nil {
		t.Fatal("expected error when account missing")
	}
}

func TestClearStaleDeviceToken_DeviceNotFound(t *testing.T) {
	mgr, uuid, _ := seedAccountWithTokens(t)
	// Device ID that doesn't exist; helper should return nil without error.
	if err := clearStaleDeviceToken(context.Background(), mgr, uuid, 99, push.DeviceTypeAPNs); err != nil {
		t.Errorf("expected nil for missing device, got %v", err)
	}
}
