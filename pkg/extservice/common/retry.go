package common

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"
)

// RetryConfig controls exponential-backoff retry for inter-service
// calls. Java's FaultTolerantHttpClient uses a similar policy.
type RetryConfig struct {
	// MaxAttempts is the total number of attempts (including the
	// initial one). Zero defaults to 3.
	MaxAttempts int
	// InitialBackoff is the wait before the first retry. Zero
	// defaults to 200ms.
	InitialBackoff time.Duration
	// MaxBackoff caps the exponential growth. Zero defaults to 5s.
	MaxBackoff time.Duration
	// Jitter, when true, applies +/- 50% randomization to each
	// backoff to avoid thundering herd. Defaults to true via the
	// applied helper.
	Jitter bool
}

func (c RetryConfig) applied() RetryConfig {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 3
	}
	if c.InitialBackoff <= 0 {
		c.InitialBackoff = 200 * time.Millisecond
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 5 * time.Second
	}
	c.Jitter = true
	return c
}

// Retryable marks an error as worth retrying.
type Retryable interface {
	Retryable() bool
}

// IsRetryable reports whether err implements Retryable and returns true.
// errors that don't implement the interface are considered non-retryable
// (the caller used WithRetry on operations whose error shape determines
// retry semantics).
func IsRetryable(err error) bool {
	var r Retryable
	if errors.As(err, &r) {
		return r.Retryable()
	}
	return false
}

// WithRetry runs fn up to cfg.MaxAttempts times with exponential
// backoff, returning the last error on exhaustion or nil on first
// success. ctx cancellation aborts immediately. Errors that are not
// Retryable end the loop early.
//
// Generic over R so callers don't need a manual nil-zero juggle for
// non-pointer returns.
func WithRetry[R any](ctx context.Context, cfg RetryConfig, fn func(context.Context) (R, error)) (R, error) {
	cfg = cfg.applied()
	var (
		zero R
		err  error
	)
	backoff := cfg.InitialBackoff
	for attempt := 0; attempt < cfg.MaxAttempts; attempt++ {
		if attempt > 0 {
			wait := backoff
			if cfg.Jitter {
				wait = jittered(backoff)
			}
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return zero, ctx.Err()
			case <-t.C:
			}
			backoff *= 2
			if backoff > cfg.MaxBackoff {
				backoff = cfg.MaxBackoff
			}
		}
		var res R
		res, err = fn(ctx)
		if err == nil {
			return res, nil
		}
		if !IsRetryable(err) {
			return zero, err
		}
	}
	return zero, err
}

// jittered returns d randomized by +/- 50%. Jitter is a timing
// nudge, not a security primitive, so math/rand/v2 is acceptable.
// #nosec G404 -- not security-sensitive
func jittered(d time.Duration) time.Duration {
	scale := 0.5 + rand.Float64()
	return time.Duration(float64(d) * scale)
}
