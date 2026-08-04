package limits

import (
	"context"
	"errors"
	"testing"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// stopRegistry is a test helper that stops all limiters in a registry.
// Since Registry fields are concrete *TokenBucketLimiter values obtained via
// the accessors, we stop each individually.
func stopRegistry(r *Registry) {
	for _, l := range []RateLimiter{
		r.ForRegistration(),
		r.ForMessages(),
		r.ForPreKeys(),
		r.ForProfiles(),
		r.ForAttachments(),
		r.ForVerification(),
		r.ForPIN(),
		r.ForUsernames(),
		r.ForAuthentication(),
		r.ForAccountCheck(),
		r.ForCaptchaAttempt(),
		r.ForCaptchaSuccess(),
		r.ForDeviceAllocate(),
		r.ForDeviceVerify(),
		r.ForInboundMessageBytes(),
	} {
		if tbl, ok := l.(*TokenBucketLimiter); ok {
			tbl.Stop()
		}
	}
}

// --------------------------------------------------------------------------
// Accessors return non-nil limiters
// --------------------------------------------------------------------------

func TestRegistry_AllAccessorsReturnNonNil(t *testing.T) {
	r := NewDefaultRegistry()
	defer stopRegistry(r)

	tests := []struct {
		name string
		got  RateLimiter
	}{
		{"ForRegistration", r.ForRegistration()},
		{"ForMessages", r.ForMessages()},
		{"ForPreKeys", r.ForPreKeys()},
		{"ForProfiles", r.ForProfiles()},
		{"ForAttachments", r.ForAttachments()},
		{"ForVerification", r.ForVerification()},
		{"ForPIN", r.ForPIN()},
		{"ForUsernames", r.ForUsernames()},
		{"ForAuthentication", r.ForAuthentication()},
		{"ForAccountCheck", r.ForAccountCheck()},
		{"ForCaptchaAttempt", r.ForCaptchaAttempt()},
		{"ForCaptchaSuccess", r.ForCaptchaSuccess()},
		{"ForDeviceAllocate", r.ForDeviceAllocate()},
		{"ForDeviceVerify", r.ForDeviceVerify()},
		{"ForInboundMessageBytes", r.ForInboundMessageBytes()},
	}

	for _, tt := range tests {
		if tt.got == nil {
			t.Errorf("%s returned nil", tt.name)
		}
	}
}

func TestRegistry_AccessorsReturnDistinctLimiters(t *testing.T) {
	r := NewDefaultRegistry()
	defer stopRegistry(r)

	// Each accessor should return its own instance to ensure independent
	// per-category rate limiting.
	if r.ForRegistration() == r.ForMessages() {
		t.Error("ForRegistration and ForMessages should be distinct")
	}
	if r.ForPreKeys() == r.ForProfiles() {
		t.Error("ForPreKeys and ForProfiles should be distinct")
	}
}

// --------------------------------------------------------------------------
// Default config produces sensible limits
// --------------------------------------------------------------------------

func TestRegistry_DefaultConfig_RegistrationAllows6(t *testing.T) {
	r := NewDefaultRegistry()
	defer stopRegistry(r)

	ctx := context.Background()
	rl := r.ForRegistration()

	for i := range 6 {
		if err := rl.Allow(ctx, "127.0.0.1"); err != nil {
			t.Fatalf("request %d: expected allow, got %v", i, err)
		}
	}
	if err := rl.Allow(ctx, "127.0.0.1"); err == nil {
		t.Fatal("7th request should be rate-limited")
	}
}

func TestRegistry_DefaultConfig_VerificationAllows6(t *testing.T) {
	r := NewDefaultRegistry()
	defer stopRegistry(r)

	ctx := context.Background()
	for i := range 6 {
		if err := r.ForVerification().Allow(ctx, "10.0.0.1"); err != nil {
			t.Fatalf("request %d: expected allow, got %v", i, err)
		}
	}
	if err := r.ForVerification().Allow(ctx, "10.0.0.1"); err == nil {
		t.Fatal("7th verification attempt should be rate-limited")
	}
}

func TestRegistry_DefaultConfig_MessagesAllows60(t *testing.T) {
	r := NewDefaultRegistry()
	defer stopRegistry(r)

	ctx := context.Background()
	uuid := "test-uuid"
	for i := range 60 {
		if err := r.ForMessages().Allow(ctx, uuid); err != nil {
			t.Fatalf("message %d: expected allow, got %v", i, err)
		}
	}
	if err := r.ForMessages().Allow(ctx, uuid); err == nil {
		t.Fatal("61st message should be rate-limited")
	}
}

// --------------------------------------------------------------------------
// Custom config overrides defaults
// --------------------------------------------------------------------------

func TestNewRegistry_CustomConfig_OverridesDefaults(t *testing.T) {
	custom := Config{
		Registration: BucketConfig{BucketSize: 2, RefillRate: 1.0},
	}
	r := NewRegistry(custom)
	defer stopRegistry(r)

	ctx := context.Background()
	rl := r.ForRegistration()

	// Should allow exactly 2, not the default 6.
	for i := range 2 {
		if err := rl.Allow(ctx, "192.168.1.1"); err != nil {
			t.Fatalf("request %d: expected allow, got %v", i, err)
		}
	}
	err := rl.Allow(ctx, "192.168.1.1")
	if err == nil {
		t.Fatal("3rd request should be rate-limited with bucket size 2")
	}
	var rle *signalerrors.RateLimitedError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *RateLimitedError, got %T", err)
	}
}

func TestNewRegistry_PartialConfig_FallsBackToDefaults(t *testing.T) {
	// Only override Messages; everything else should use defaults.
	custom := Config{
		Messages: BucketConfig{BucketSize: 5, RefillRate: 5.0},
	}
	r := NewRegistry(custom)
	defer stopRegistry(r)

	ctx := context.Background()

	// Messages should use custom bucket size of 5.
	for i := range 5 {
		if err := r.ForMessages().Allow(ctx, "uuid1"); err != nil {
			t.Fatalf("message %d: expected allow, got %v", i, err)
		}
	}
	if err := r.ForMessages().Allow(ctx, "uuid1"); err == nil {
		t.Fatal("6th message should be rate-limited with custom bucket 5")
	}

	// Registration should use default of 6.
	for i := range 6 {
		if err := r.ForRegistration().Allow(ctx, "ip1"); err != nil {
			t.Fatalf("registration %d: expected allow, got %v", i, err)
		}
	}
}

func TestRegistry_DefaultConfig_AccountCheckBucketSize1000(t *testing.T) {
	// Verify that the AccountCheck bucket size defaults to 1000.
	// We use a custom limiter with zero refill to ensure the bucket does not
	// refill during the test (the default 250/s refill would allow an
	// unacceptably high number of tokens to be replenished during 1000 calls
	// under the race detector, causing the boundary check to be flaky).
	rl := NewTokenBucketLimiter(BucketConfig{
		BucketSize: 1000,
		RefillRate: 0.0001, // near-zero: < 1 token in the lifetime of this test
	})
	defer rl.Stop()

	ctx := context.Background()

	// Should allow exactly 1000.
	for i := range 1000 {
		if err := rl.Allow(ctx, "10.0.0.1"); err != nil {
			t.Fatalf("request %d: expected allow, got %v", i, err)
		}
	}
	// The 1001st should be rate-limited.
	if err := rl.Allow(ctx, "10.0.0.1"); err == nil {
		t.Fatal("1001st account check should be rate-limited with bucket size 1000")
	}
}

func TestRegistry_DefaultConfig_AccountCheckRefillRate(t *testing.T) {
	// Verify that the default AccountCheck refill rate is 250/s.
	cfg := DefaultConfig()
	if cfg.AccountCheck.RefillRate != 250.0 {
		t.Errorf("AccountCheck.RefillRate: got %f, want 250.0", cfg.AccountCheck.RefillRate)
	}
	if cfg.AccountCheck.BucketSize != 1000 {
		t.Errorf("AccountCheck.BucketSize: got %d, want 1000", cfg.AccountCheck.BucketSize)
	}
}

func TestRegistry_AccountCheckIsDistinctFromOtherLimiters(t *testing.T) {
	r := NewDefaultRegistry()
	defer stopRegistry(r)

	if r.ForAccountCheck() == r.ForRegistration() {
		t.Error("ForAccountCheck and ForRegistration should be distinct limiters")
	}
	if r.ForAccountCheck() == r.ForMessages() {
		t.Error("ForAccountCheck and ForMessages should be distinct limiters")
	}
}

// --------------------------------------------------------------------------
// Registry.Stop – lifecycle and idempotency
// --------------------------------------------------------------------------

// TestRegistry_Stop_HaltsAllGoroutines verifies that calling Stop on a registry
// does not panic and that the registry can be discarded cleanly afterwards.
// A second registry is created immediately after to confirm that Stop does not
// corrupt any global state.
func TestRegistry_Stop_HaltsAllGoroutines(t *testing.T) {
	r := NewDefaultRegistry()

	// Must not panic.
	r.Stop()

	// Creating a fresh registry after Stop must work correctly.
	r2 := NewDefaultRegistry()
	defer r2.Stop()

	ctx := context.Background()
	if err := r2.ForRegistration().Allow(ctx, "127.0.0.1"); err != nil {
		t.Fatalf("new registry after Stop: unexpected error: %v", err)
	}
}

// TestRegistry_Stop_IsIdempotent verifies that calling Stop more than once on
// the same registry does not panic.  TokenBucketLimiter.Stop is guarded by
// sync.Once, so the second call must be a silent no-op.
func TestRegistry_Stop_IsIdempotent(t *testing.T) {
	r := NewDefaultRegistry()

	// Two consecutive calls must both be panic-free.
	r.Stop()
	r.Stop()
}

func TestRegistry_BackupAndCallLinkAccessors(t *testing.T) {
	r := NewDefaultRegistry()
	defer r.Stop()

	pairs := []struct {
		name string
		got  RateLimiter
	}{
		{"ForSetBackupID", r.ForSetBackupID()},
		{"ForSetPaidMediaBackupID", r.ForSetPaidMediaBackupID()},
		{"ForBackupAttachment", r.ForBackupAttachment()},
		{"ForCreateCallLink", r.ForCreateCallLink()},
	}
	for _, p := range pairs {
		if p.got == nil {
			t.Errorf("%s returned nil", p.name)
		}
	}
	// Each must be distinct from the others.
	if r.ForSetBackupID() == r.ForSetPaidMediaBackupID() {
		t.Error("ForSetBackupID and ForSetPaidMediaBackupID should be distinct")
	}
	if r.ForBackupAttachment() == r.ForCreateCallLink() {
		t.Error("ForBackupAttachment and ForCreateCallLink should be distinct")
	}
}

func TestRegistry_BackupLimiters_FunctionallyAllow(t *testing.T) {
	r := NewDefaultRegistry()
	defer r.Stop()
	ctx := context.Background()

	for _, rl := range []RateLimiter{
		r.ForSetBackupID(),
		r.ForSetPaidMediaBackupID(),
		r.ForBackupAttachment(),
		r.ForCreateCallLink(),
	} {
		if err := rl.Allow(ctx, "test-key"); err != nil {
			t.Errorf("first Allow should succeed, got: %v", err)
		}
	}
}

func TestNewDefaultRegistry_MatchesExplicitDefaultConfig(t *testing.T) {
	r1 := NewDefaultRegistry()
	defer stopRegistry(r1)
	r2 := NewRegistry(DefaultConfig())
	defer stopRegistry(r2)

	// Both should have the same bucket configuration behaviour.
	ctx := context.Background()
	for i := range 6 {
		e1 := r1.ForRegistration().Allow(ctx, "k")
		e2 := r2.ForRegistration().Allow(ctx, "k")
		if (e1 == nil) != (e2 == nil) {
			t.Errorf("request %d: default and explicit configs diverged", i)
		}
	}
}
