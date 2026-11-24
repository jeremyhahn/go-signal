package spam

import "context"

// DenyAllChecker is a SpamChecker that blocks every message. It is the
// fail-closed counterpart to NoOpChecker and is installed only as a
// last-resort safety net when a production deployment is constructed
// without a real spam-checking policy. Blocking (rather than allowing)
// is the safe failure mode: it surfaces the misconfiguration loudly
// instead of silently admitting unfiltered traffic.
type DenyAllChecker struct{}

// Check always returns SpamCheckBlock with a nil error.
func (DenyAllChecker) Check(_ context.Context, _ *CheckContext) (SpamCheckResult, error) {
	return SpamCheckBlock, nil
}

// DenyAllFraudChecker treats every registration as fraudulent. It is the
// fail-closed counterpart to NoOpFraudChecker, installed only when a
// production deployment lacks a configured fraud checker so registrations
// are rejected rather than silently admitted.
type DenyAllFraudChecker struct{}

// Check always returns true (treat as fraudulent / block).
func (DenyAllFraudChecker) Check(_ context.Context, _ *RegistrationFraudRequest) bool {
	return true
}
