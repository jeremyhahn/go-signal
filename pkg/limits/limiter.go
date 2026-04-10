package limits

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// RateLimiter is the core interface for rate limiting operations.
// Implementations must be safe for concurrent use.
type RateLimiter interface {
	// Allow checks whether one token is available for key. It returns
	// *signalerrors.RateLimitedError when the limit is exceeded.
	Allow(ctx context.Context, key string) error

	// AllowN checks whether n tokens are available for key. It returns
	// *signalerrors.RateLimitedError when the limit is exceeded.
	AllowN(ctx context.Context, key string, n int) error
}

// bucket is the per-key state for a token-bucket limiter.
// All fields are accessed atomically to avoid mutex contention.
type bucket struct {
	// tokens holds the current token count scaled by tokenScale to allow
	// sub-integer precision using integer atomics.
	tokens int64
	// lastRefill is the Unix nanosecond timestamp of the last refill.
	lastRefill int64
	// lastAccess is the Unix nanosecond timestamp of the most recent
	// Allow/AllowN call; used by the cleanup goroutine.
	lastAccess int64
}

// tokenScale converts float64 tokens to a fixed-point int64 representation.
// Using 1e9 gives nanosecond-level precision for refill calculations.
const tokenScale = 1e9

// TokenBucketLimiter is a lock-free, in-memory token-bucket rate limiter
// backed by sync.Map for per-key bucket storage.
type TokenBucketLimiter struct {
	cfg     BucketConfig
	nowFn   func() int64 // returns UnixNano; injectable for testing
	buckets sync.Map     // key string -> *bucket

	stopCleanup chan struct{}
	cleanupDone chan struct{}
	stopOnce    sync.Once
}

// NewTokenBucketLimiter creates a new TokenBucketLimiter from cfg and starts
// the background cleanup goroutine. Call Stop to release resources.
func NewTokenBucketLimiter(cfg BucketConfig) *TokenBucketLimiter {
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = defaultCleanupInterval
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = defaultStaleAfter
	}

	l := &TokenBucketLimiter{
		cfg:         cfg,
		nowFn:       func() int64 { return time.Now().UnixNano() },
		stopCleanup: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	go l.cleanupLoop()
	return l
}

// newTokenBucketLimiterWithClock creates a limiter with an injectable clock.
// This is used only by tests to exercise time-dependent refill logic without
// real sleeps.
func newTokenBucketLimiterWithClock(cfg BucketConfig, nowFn func() int64) *TokenBucketLimiter {
	if cfg.CleanupInterval <= 0 {
		cfg.CleanupInterval = defaultCleanupInterval
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = defaultStaleAfter
	}
	l := &TokenBucketLimiter{
		cfg:         cfg,
		nowFn:       nowFn,
		stopCleanup: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	go l.cleanupLoop()
	return l
}

// Stop halts the background cleanup goroutine and waits for it to exit.
// It is safe to call Stop multiple times; subsequent calls are no-ops.
func (l *TokenBucketLimiter) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopCleanup)
		<-l.cleanupDone
	})
}

// Allow implements RateLimiter. It consumes one token for the given key.
func (l *TokenBucketLimiter) Allow(ctx context.Context, key string) error {
	return l.AllowN(ctx, key, 1)
}

// AllowN implements RateLimiter. It consumes n tokens for the given key.
// A non-positive n is treated as 1.
func (l *TokenBucketLimiter) AllowN(_ context.Context, key string, n int) error {
	if n <= 0 {
		n = 1
	}
	b := l.getOrCreate(key)
	now := l.nowFn()
	atomic.StoreInt64(&b.lastAccess, now)

	// Refill tokens based on elapsed time since last refill.
	l.refill(b, now)

	// Attempt to consume n tokens via a CAS loop.
	cost := int64(n) * tokenScale
	for {
		current := atomic.LoadInt64(&b.tokens)
		if current < cost {
			return l.rateLimitError(cost - current)
		}
		next := current - cost
		if atomic.CompareAndSwapInt64(&b.tokens, current, next) {
			return nil
		}
		// Another goroutine updated tokens concurrently; retry.
	}
}

// getOrCreate returns the existing bucket for key or atomically inserts a new
// full bucket. sync.Map.LoadOrStore guarantees a single canonical bucket per
// key under concurrent calls without an additional mutex.
func (l *TokenBucketLimiter) getOrCreate(key string) *bucket {
	now := l.nowFn()
	b := &bucket{
		tokens:     int64(l.cfg.BucketSize) * tokenScale,
		lastRefill: now,
		lastAccess: now,
	}
	actual, _ := l.buckets.LoadOrStore(key, b)
	return actual.(*bucket)
}

// refill adds tokens to b based on elapsed time since the last refill.
// It uses a CAS loop on lastRefill to avoid double-counting concurrent
// refills without holding a mutex.
func (l *TokenBucketLimiter) refill(b *bucket, now int64) {
	for {
		last := atomic.LoadInt64(&b.lastRefill)
		if now <= last {
			return
		}
		elapsed := float64(now-last) / float64(time.Second)
		max := int64(l.cfg.BucketSize) * tokenScale
		// Clamp the floating-point product before converting to int64 to
		// prevent undefined behaviour when the result exceeds math.MaxInt64
		// (e.g. an extremely high RefillRate or a large elapsed duration).
		rawAdd := elapsed * l.cfg.RefillRate * tokenScale
		if rawAdd <= 0 {
			return
		}
		var toAdd int64
		if rawAdd >= float64(max) {
			toAdd = max
		} else {
			toAdd = int64(rawAdd)
		}
		if toAdd <= 0 {
			return
		}
		// Claim the refill window by advancing lastRefill.
		if !atomic.CompareAndSwapInt64(&b.lastRefill, last, now) {
			// Another goroutine advanced lastRefill; they will add the tokens.
			continue
		}
		// We own the refill window; apply tokens with ceiling at max.
		// Guard against int64 overflow: if cur+toAdd would wrap past max,
		// clamp directly to max without performing the wrapping addition.
		for {
			cur := atomic.LoadInt64(&b.tokens)
			var next int64
			if toAdd > max-cur {
				next = max
			} else {
				next = cur + toAdd
			}
			if atomic.CompareAndSwapInt64(&b.tokens, cur, next) {
				return
			}
		}
	}
}

// rateLimitError computes the retry-after duration from the token deficit and
// returns a *signalerrors.RateLimitedError.
func (l *TokenBucketLimiter) rateLimitError(deficit int64) *signalerrors.RateLimitedError {
	// deficit is in scaled token units; convert to seconds.
	deficitTokens := float64(deficit) / tokenScale
	retryAfterSec := int64(math.Ceil(deficitTokens / l.cfg.RefillRate))
	if retryAfterSec < 1 {
		retryAfterSec = 1
	}
	return signalerrors.NewRateLimitedError(retryAfterSec)
}

// cleanupLoop periodically removes stale buckets to prevent unbounded memory
// growth from keys that are no longer active.
func (l *TokenBucketLimiter) cleanupLoop() {
	defer close(l.cleanupDone)

	ticker := time.NewTicker(l.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCleanup:
			return
		case <-ticker.C:
			l.purgeStale()
		}
	}
}

// purgeStale removes all buckets whose lastAccess timestamp is older than
// the configured StaleAfter duration.
func (l *TokenBucketLimiter) purgeStale() {
	threshold := l.nowFn() - l.cfg.StaleAfter.Nanoseconds()
	l.buckets.Range(func(k, v any) bool {
		b := v.(*bucket)
		if atomic.LoadInt64(&b.lastAccess) < threshold {
			l.buckets.Delete(k)
		}
		return true
	})
}
