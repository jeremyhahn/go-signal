package limits

import (
	"testing"
)

func TestDefaultConfig_RegistrationDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Registration.BucketSize != 6 {
		t.Errorf("Registration.BucketSize: got %d, want 6", cfg.Registration.BucketSize)
	}
	// 6 per 30s = 0.2/s
	wantRate := float64(6) / 30.0
	if cfg.Registration.RefillRate != wantRate {
		t.Errorf("Registration.RefillRate: got %f, want %f", cfg.Registration.RefillRate, wantRate)
	}
}

func TestDefaultConfig_MessagesDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Messages.BucketSize != 60 {
		t.Errorf("Messages.BucketSize: got %d, want 60", cfg.Messages.BucketSize)
	}
	if cfg.Messages.RefillRate != 60.0 {
		t.Errorf("Messages.RefillRate: got %f, want 60", cfg.Messages.RefillRate)
	}
}

func TestDefaultConfig_PreKeysDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.PreKeys.BucketSize != 6 {
		t.Errorf("PreKeys.BucketSize: got %d, want 6", cfg.PreKeys.BucketSize)
	}
	wantRate := float64(6) / 600.0
	if cfg.PreKeys.RefillRate != wantRate {
		t.Errorf("PreKeys.RefillRate: got %f, want %f", cfg.PreKeys.RefillRate, wantRate)
	}
}

func TestDefaultConfig_ProfilesDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Profiles.BucketSize != 4320 {
		t.Errorf("Profiles.BucketSize: got %d, want 4320", cfg.Profiles.BucketSize)
	}
	wantRate := float64(4320) / 20.0
	if cfg.Profiles.RefillRate != wantRate {
		t.Errorf("Profiles.RefillRate: got %f, want %f", cfg.Profiles.RefillRate, wantRate)
	}
}

func TestDefaultConfig_AttachmentsDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Attachments.BucketSize != 50 {
		t.Errorf("Attachments.BucketSize: got %d, want 50", cfg.Attachments.BucketSize)
	}
	wantRate := float64(50) / 1.2
	if cfg.Attachments.RefillRate != wantRate {
		t.Errorf("Attachments.RefillRate: got %f, want %f", cfg.Attachments.RefillRate, wantRate)
	}
}

func TestDefaultConfig_VerificationDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Verification.BucketSize != 6 {
		t.Errorf("Verification.BucketSize: got %d, want 6", cfg.Verification.BucketSize)
	}
	wantRate := float64(6) / 30.0
	if cfg.Verification.RefillRate != wantRate {
		t.Errorf("Verification.RefillRate: got %f, want %f", cfg.Verification.RefillRate, wantRate)
	}
}

func TestDefaultConfig_PINDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.PIN.BucketSize != 10 {
		t.Errorf("PIN.BucketSize: got %d, want 10", cfg.PIN.BucketSize)
	}
	wantRate := float64(10) / 86400.0
	if cfg.PIN.RefillRate != wantRate {
		t.Errorf("PIN.RefillRate: got %f, want %f", cfg.PIN.RefillRate, wantRate)
	}
}

func TestDefaultConfig_UsernamesDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Usernames.BucketSize != 100 {
		t.Errorf("Usernames.BucketSize: got %d, want 100", cfg.Usernames.BucketSize)
	}
	wantRate := float64(100) / 60.0
	if cfg.Usernames.RefillRate != wantRate {
		t.Errorf("Usernames.RefillRate: got %f, want %f", cfg.Usernames.RefillRate, wantRate)
	}
}

func TestDefaultConfig_AuthenticationDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Authentication.BucketSize != 10 {
		t.Errorf("Authentication.BucketSize: got %d, want 10", cfg.Authentication.BucketSize)
	}
	wantRate := float64(10) / 60.0
	if cfg.Authentication.RefillRate != wantRate {
		t.Errorf("Authentication.RefillRate: got %f, want %f", cfg.Authentication.RefillRate, wantRate)
	}
}

func TestDefaultConfig_AccountCheckDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AccountCheck.BucketSize != 1000 {
		t.Errorf("AccountCheck.BucketSize: got %d, want 1000", cfg.AccountCheck.BucketSize)
	}
	// 250 per second (1000 per 4 seconds)
	if cfg.AccountCheck.RefillRate != 250.0 {
		t.Errorf("AccountCheck.RefillRate: got %f, want 250.0", cfg.AccountCheck.RefillRate)
	}
}

func TestDefaultConfig_CaptchaAttemptDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.CaptchaAttempt.BucketSize != 10 {
		t.Errorf("CaptchaAttempt.BucketSize: got %d, want 10", cfg.CaptchaAttempt.BucketSize)
	}
	wantRate := float64(10) / 86400.0
	if cfg.CaptchaAttempt.RefillRate != wantRate {
		t.Errorf("CaptchaAttempt.RefillRate: got %f, want %f", cfg.CaptchaAttempt.RefillRate, wantRate)
	}
}

func TestDefaultConfig_CaptchaSuccessDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.CaptchaSuccess.BucketSize != 2 {
		t.Errorf("CaptchaSuccess.BucketSize: got %d, want 2", cfg.CaptchaSuccess.BucketSize)
	}
	wantRate := float64(2) / 86400.0
	if cfg.CaptchaSuccess.RefillRate != wantRate {
		t.Errorf("CaptchaSuccess.RefillRate: got %f, want %f", cfg.CaptchaSuccess.RefillRate, wantRate)
	}
}

func TestDefaultConfig_DeviceAllocateDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DeviceAllocate.BucketSize != 6 {
		t.Errorf("DeviceAllocate.BucketSize: got %d, want 6", cfg.DeviceAllocate.BucketSize)
	}
	wantRate := float64(6) / 120.0
	if cfg.DeviceAllocate.RefillRate != wantRate {
		t.Errorf("DeviceAllocate.RefillRate: got %f, want %f", cfg.DeviceAllocate.RefillRate, wantRate)
	}
}

func TestDefaultConfig_DeviceVerifyDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.DeviceVerify.BucketSize != 6 {
		t.Errorf("DeviceVerify.BucketSize: got %d, want 6", cfg.DeviceVerify.BucketSize)
	}
	wantRate := float64(6) / 60.0
	if cfg.DeviceVerify.RefillRate != wantRate {
		t.Errorf("DeviceVerify.RefillRate: got %f, want %f", cfg.DeviceVerify.RefillRate, wantRate)
	}
}

func TestDefaultConfig_InboundMessageBytesDefaults(t *testing.T) {
	cfg := DefaultConfig()
	wantSize := 256 * 1024 * 1024
	if cfg.InboundMessageBytes.BucketSize != wantSize {
		t.Errorf("InboundMessageBytes.BucketSize: got %d, want %d", cfg.InboundMessageBytes.BucketSize, wantSize)
	}
	wantRate := float64(256*1024*1024) / 60.0
	if cfg.InboundMessageBytes.RefillRate != wantRate {
		t.Errorf("InboundMessageBytes.RefillRate: got %f, want %f", cfg.InboundMessageBytes.RefillRate, wantRate)
	}
}

func TestDefaultConfig_AllBucketSizesPositive(t *testing.T) {
	cfg := DefaultConfig()
	configs := map[string]BucketConfig{
		"Registration":        cfg.Registration,
		"Messages":            cfg.Messages,
		"PreKeys":             cfg.PreKeys,
		"Profiles":            cfg.Profiles,
		"Attachments":         cfg.Attachments,
		"Verification":        cfg.Verification,
		"PIN":                 cfg.PIN,
		"Usernames":           cfg.Usernames,
		"Authentication":      cfg.Authentication,
		"AccountCheck":        cfg.AccountCheck,
		"CaptchaAttempt":      cfg.CaptchaAttempt,
		"CaptchaSuccess":      cfg.CaptchaSuccess,
		"DeviceAllocate":      cfg.DeviceAllocate,
		"DeviceVerify":        cfg.DeviceVerify,
		"InboundMessageBytes": cfg.InboundMessageBytes,
	}
	for name, c := range configs {
		if c.BucketSize <= 0 {
			t.Errorf("%s: BucketSize must be positive, got %d", name, c.BucketSize)
		}
		if c.RefillRate <= 0 {
			t.Errorf("%s: RefillRate must be positive, got %f", name, c.RefillRate)
		}
	}
}

func TestMergeConfig_OverrideUsedWhenComplete(t *testing.T) {
	override := BucketConfig{BucketSize: 99, RefillRate: 7.5}
	fallback := BucketConfig{BucketSize: 1, RefillRate: 0.5}
	got := mergeConfig(override, fallback)
	if got.BucketSize != 99 || got.RefillRate != 7.5 {
		t.Errorf("expected override, got %+v", got)
	}
}

func TestMergeConfig_FallbackUsedWhenZeroBucketSize(t *testing.T) {
	override := BucketConfig{BucketSize: 0, RefillRate: 7.5}
	fallback := BucketConfig{BucketSize: 10, RefillRate: 1.0}
	got := mergeConfig(override, fallback)
	if got.BucketSize != 10 || got.RefillRate != 1.0 {
		t.Errorf("expected fallback, got %+v", got)
	}
}

func TestMergeConfig_FallbackUsedWhenZeroRefillRate(t *testing.T) {
	override := BucketConfig{BucketSize: 5, RefillRate: 0}
	fallback := BucketConfig{BucketSize: 10, RefillRate: 1.0}
	got := mergeConfig(override, fallback)
	if got.BucketSize != 10 || got.RefillRate != 1.0 {
		t.Errorf("expected fallback, got %+v", got)
	}
}
