package spam

import "context"

// DenyAllChecker blocks every message; the fail-closed fallback when production has no spam policy.
type DenyAllChecker struct{}

// Check always returns SpamCheckBlock with a nil error.
func (DenyAllChecker) Check(_ context.Context, _ *CheckContext) (SpamCheckResult, error) {
	return SpamCheckBlock, nil
}

// DenyAllFraudChecker rejects every registration; the fail-closed fallback when production has no fraud checker.
type DenyAllFraudChecker struct{}

// Check always returns true (treat as fraudulent / block).
func (DenyAllFraudChecker) Check(_ context.Context, _ *RegistrationFraudRequest) bool {
	return true
}
