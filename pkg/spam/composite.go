package spam

import "context"

// CompositeChecker runs checkers in order: any Block wins and stops evaluation, else any Challenge, else Allow. Safe for concurrent use.
type CompositeChecker struct {
	checkers []SpamChecker
}

// NewCompositeChecker constructs a CompositeChecker from the provided slice of
// SpamCheckers. The slice is copied so that subsequent mutations to the
// original slice do not affect the checker.
func NewCompositeChecker(checkers []SpamChecker) *CompositeChecker {
	c := make([]SpamChecker, len(checkers))
	copy(c, checkers)
	return &CompositeChecker{checkers: c}
}

// Check evaluates each contained checker in order and returns the highest-
// priority result. Block beats Challenge; Challenge beats Allow. The first
// error encountered is returned alongside the result.
func (c *CompositeChecker) Check(ctx context.Context, checkCtx *CheckContext) (SpamCheckResult, error) {
	result := SpamCheckAllow
	var firstErr error

	for _, checker := range c.checkers {
		r, err := checker.Check(ctx, checkCtx)
		if err != nil && firstErr == nil {
			firstErr = err
		}

		switch r {
		case SpamCheckBlock:
			// Block is the highest priority; short-circuit immediately.
			return SpamCheckBlock, firstErr
		case SpamCheckChallenge:
			// Upgrade result to Challenge; continue checking for a potential Block.
			result = SpamCheckChallenge
		}
	}

	return result, firstErr
}
