package spam

import "context"

// NoOpChecker is a SpamChecker that unconditionally allows every message.
// It is used as the default implementation when no spam-checking policy is
// configured, ensuring the message path has zero overhead.
type NoOpChecker struct{}

// Check always returns SpamCheckAllow with a nil error.
func (n *NoOpChecker) Check(_ context.Context, _ *CheckContext) (SpamCheckResult, error) {
	return SpamCheckAllow, nil
}
