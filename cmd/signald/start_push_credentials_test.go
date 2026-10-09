package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestBuildPushManager_UnopenableFCMCredentialFailsStartup: a configured FCM
// credential that cannot be opened must fail startup, not leave the no-op
// provider silently accepting and dropping every Android notification.
func TestBuildPushManager_UnopenableFCMCredentialFailsStartup(t *testing.T) {
	cfg := config.PushConfig{FCM: config.FCMConfig{
		Credentials: secrets.MustNewSecureString(context.Background(), `{"type":"service_account"}`),
	}}

	mgr, err := buildPushManager(canceledCtx(), cfg, discardLogger())
	if err == nil {
		t.Fatalf("buildPushManager succeeded with an unopenable FCM credential: %v", mgr)
	}
	var startup *StartupError
	if !errors.As(err, &startup) || startup.Stage != "fcm" {
		t.Fatalf("error = %v, want *StartupError at stage fcm", err)
	}
	var unavailable *secrets.UnavailableSecretError
	if !errors.As(err, &unavailable) {
		t.Fatalf("error = %v, want it to wrap *secrets.UnavailableSecretError", err)
	}
}

// TestBuildPushManager_AbsentFCMCredentialIsOptional: an FCM credential that
// was never configured is a legitimate deployment and must not fail startup.
func TestBuildPushManager_AbsentFCMCredentialIsOptional(t *testing.T) {
	for name, creds := range map[string]*secrets.SecureString{
		"nil":   nil,
		"unset": secrets.MustNewSecureString(context.Background(), ""),
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config.PushConfig{FCM: config.FCMConfig{Credentials: creds}}
			mgr, err := buildPushManager(context.Background(), cfg, discardLogger())
			if err != nil {
				t.Fatalf("buildPushManager: %v", err)
			}
			if mgr == nil {
				t.Fatal("buildPushManager returned a nil manager")
			}
		})
	}
}

// TestBuildPushManager_UnopenableAPNsKeyFailsStartup: same rule for the APNs
// signing key.
func TestBuildPushManager_UnopenableAPNsKeyFailsStartup(t *testing.T) {
	cfg := config.PushConfig{APN: config.APNConfig{
		TeamID: "team", KeyID: "key", BundleID: "bundle",
		PrivateKey: secrets.MustNewSecureString(context.Background(), "pem"),
	}}

	_, err := buildPushManager(canceledCtx(), cfg, discardLogger())
	var startup *StartupError
	if !errors.As(err, &startup) || startup.Stage != "apns" {
		t.Fatalf("error = %v, want *StartupError at stage apns", err)
	}
	var unavailable *secrets.UnavailableSecretError
	if !errors.As(err, &unavailable) {
		t.Fatalf("error = %v, want it to wrap *secrets.UnavailableSecretError", err)
	}
}
