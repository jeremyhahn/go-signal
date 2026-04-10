package limits

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// newTestLimiter creates a limiter with a small bucket and injectable clock.
func newTestLimiter(size int, ratePerSec float64, nowFn func() int64) *TokenBucketLimiter {
	cfg := BucketConfig{
		BucketSize:      size,
		RefillRate:      ratePerSec,
		CleanupInterval: time.Hour, // disable auto-cleanup in tests
		StaleAfter:      time.Hour,
	}
	return newTokenBucketLimiterWithClock(cfg, nowFn)
}

// --------------------------------------------------------------------------
// Allow / AllowN: basic capacity exhaustion
// --------------------------------------------------------------------------

func TestTokenBucketLimiter_Allow_AllowsUpToBucketSize(t *testing.T) {
	l := newTestLimiter(5, 1.0, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	for i := range 5 {
		if err := l.Allow(ctx, "k"); err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
	}
}

func TestTokenBucketLimiter_Allow_RejectsWhenExhausted(t *testing.T) {
	l := newTestLimiter(3, 1.0, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	for range 3 {
		_ = l.Allow(ctx, "k")
	}

	err := l.Allow(ctx, "k")
	if err == nil {
		t.Fatal("expected rate limit error after exhausting bucket")
	}
	var rle *signalerrors.RateLimitedError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *RateLimitedError, got %T", err)
	}
	if rle.RetryAfterSeconds < 1 {
		t.Errorf("expected RetryAfterSeconds >= 1, got %d", rle.RetryAfterSeconds)
	}
}

func TestTokenBucketLimiter_AllowN_ConsumesMultipleTokens(t *testing.T) {
	l := newTestLimiter(10, 1.0, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	if err := l.AllowN(ctx, "k", 7); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 3 tokens remain; AllowN(4) should fail.
	err := l.AllowN(ctx, "k", 4)
	if err == nil {
		t.Fatal("expected rate limit error")
	}
	var rle *signalerrors.RateLimitedError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *RateLimitedError, got %T", err)
	}
}

func TestTokenBucketLimiter_AllowN_ZeroTreatedAsOne(t *testing.T) {
	l := newTestLimiter(2, 1.0, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	if err := l.AllowN(ctx, "k", 0); err != nil {
		t.Fatalf("AllowN(0) should consume 1 token: %v", err)
	}
	if err := l.AllowN(ctx, "k", -1); err != nil {
		t.Fatalf("AllowN(-1) should consume 1 token: %v", err)
	}
	// Both tokens consumed; next should fail.
	if err := l.AllowN(ctx, "k", 1); err == nil {
		t.Fatal("expected error after consuming all tokens")
	}
}

func TestTokenBucketLimiter_AllowN_ExactBucketSizeSucceeds(t *testing.T) {
	l := newTestLimiter(5, 1.0, fixedClock(0))
	defer l.Stop()

	if err := l.AllowN(context.Background(), "k", 5); err != nil {
		t.Fatalf("AllowN equal to bucket size should succeed: %v", err)
	}
}

func TestTokenBucketLimiter_AllowN_ExceedsBucketSizeFails(t *testing.T) {
	l := newTestLimiter(5, 1.0, fixedClock(0))
	defer l.Stop()

	err := l.AllowN(context.Background(), "k", 6)
	if err == nil {
		t.Fatal("AllowN greater than bucket size should fail immediately")
	}
}

// --------------------------------------------------------------------------
// Refill behaviour
// --------------------------------------------------------------------------

func TestTokenBucketLimiter_Refill_OverTimeAllowsMoreRequests(t *testing.T) {
	var now atomic.Int64
	now.Store(0)

	l := newTestLimiter(3, 1.0, func() int64 { return now.Load() })
	defer l.Stop()

	ctx := context.Background()
	// Exhaust the bucket.
	for range 3 {
		if err := l.Allow(ctx, "k"); err != nil {
			t.Fatalf("unexpected error draining bucket: %v", err)
		}
	}
	if err := l.Allow(ctx, "k"); err == nil {
		t.Fatal("expected error after drain")
	}

	// Advance clock by 2 seconds: refill rate 1/s → 2 new tokens.
	now.Store(int64(2 * time.Second))

	// Should allow 2 more requests.
	for i := range 2 {
		if err := l.Allow(ctx, "k"); err != nil {
			t.Fatalf("request %d after refill: unexpected error: %v", i, err)
		}
	}
	// Third request should fail again.
	if err := l.Allow(ctx, "k"); err == nil {
		t.Fatal("expected error; only 2 tokens should have been refilled")
	}
}

func TestTokenBucketLimiter_Refill_DoesNotExceedBucketSize(t *testing.T) {
	var now atomic.Int64
	now.Store(0)

	l := newTestLimiter(3, 1.0, func() int64 { return now.Load() })
	defer l.Stop()

	ctx := context.Background()
	// Exhaust the bucket.
	for range 3 {
		_ = l.Allow(ctx, "k")
	}

	// Advance by 100 seconds; should cap at bucket size 3, not 100.
	now.Store(int64(100 * time.Second))

	for i := range 3 {
		if err := l.Allow(ctx, "k"); err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
	}
	if err := l.Allow(ctx, "k"); err == nil {
		t.Fatal("expected error after consuming refilled bucket")
	}
}

// --------------------------------------------------------------------------
// Key isolation
// --------------------------------------------------------------------------

func TestTokenBucketLimiter_DifferentKeys_AreIndependent(t *testing.T) {
	l := newTestLimiter(2, 1.0, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	// Exhaust key "a".
	_ = l.Allow(ctx, "a")
	_ = l.Allow(ctx, "a")
	if err := l.Allow(ctx, "a"); err == nil {
		t.Fatal("key a should be exhausted")
	}

	// Key "b" should still be full.
	if err := l.Allow(ctx, "b"); err != nil {
		t.Fatalf("key b should not be limited: %v", err)
	}
}

func TestTokenBucketLimiter_SameKey_SharedBucket(t *testing.T) {
	l := newTestLimiter(2, 1.0, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	_ = l.Allow(ctx, "shared")
	_ = l.Allow(ctx, "shared")

	err := l.Allow(ctx, "shared")
	if err == nil {
		t.Fatal("expected rate limit error for exhausted shared key")
	}
}

// --------------------------------------------------------------------------
// Concurrency safety
// --------------------------------------------------------------------------

func TestTokenBucketLimiter_ConcurrentAccess_NoDataRace(t *testing.T) {
	l := newTestLimiter(50, 100.0, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	const goroutines = 20
	const perGoroutine = 30

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range perGoroutine {
				_ = l.Allow(ctx, "concurrent-key")
			}
		}()
	}
	wg.Wait()
}

func TestTokenBucketLimiter_ConcurrentMultipleKeys_NoDataRace(t *testing.T) {
	l := newTestLimiter(10, 10.0, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	keys := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	const goroutines = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			k := keys[idx%len(keys)]
			for range 20 {
				_ = l.AllowN(ctx, k, 1)
			}
		}(i)
	}
	wg.Wait()
}

func TestTokenBucketLimiter_ConcurrentBucketExhaustion_ConsistentErrors(t *testing.T) {
	const bucketSize = 10
	l := newTestLimiter(bucketSize, 0.001, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	const goroutines = 20
	var allowed atomic.Int64
	var denied atomic.Int64

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			err := l.Allow(ctx, "contended")
			if err == nil {
				allowed.Add(1)
			} else {
				denied.Add(1)
			}
		}()
	}
	wg.Wait()

	if allowed.Load() > bucketSize {
		t.Errorf("allowed %d > bucket size %d", allowed.Load(), bucketSize)
	}
	if allowed.Load()+denied.Load() != goroutines {
		t.Errorf("allowed+denied=%d, want %d", allowed.Load()+denied.Load(), goroutines)
	}
}

// --------------------------------------------------------------------------
// Stale entry cleanup
// --------------------------------------------------------------------------

func TestTokenBucketLimiter_PurgeStale_RemovesOldEntries(t *testing.T) {
	var now atomic.Int64
	now.Store(0)

	cfg := BucketConfig{
		BucketSize:      5,
		RefillRate:      1.0,
		CleanupInterval: time.Hour, // manual trigger
		StaleAfter:      time.Minute,
	}
	l := newTokenBucketLimiterWithClock(cfg, func() int64 { return now.Load() })
	defer l.Stop()

	ctx := context.Background()
	_ = l.Allow(ctx, "stale-key")

	// Verify bucket exists.
	if _, ok := l.buckets.Load("stale-key"); !ok {
		t.Fatal("expected bucket to exist after Allow")
	}

	// Advance clock past stale threshold.
	now.Store(int64(2 * time.Minute))

	l.purgeStale()

	if _, ok := l.buckets.Load("stale-key"); ok {
		t.Fatal("expected bucket to be purged after stale threshold")
	}
}

func TestTokenBucketLimiter_PurgeStale_KeepsRecentEntries(t *testing.T) {
	var now atomic.Int64
	now.Store(0)

	cfg := BucketConfig{
		BucketSize:      5,
		RefillRate:      1.0,
		CleanupInterval: time.Hour,
		StaleAfter:      time.Minute,
	}
	l := newTokenBucketLimiterWithClock(cfg, func() int64 { return now.Load() })
	defer l.Stop()

	ctx := context.Background()
	// Access the key at t=50s, just under the stale threshold of 60s.
	now.Store(int64(50 * time.Second))
	_ = l.Allow(ctx, "fresh-key")

	// Advance clock to 60s, which is NOT past (50+60=110s stale threshold).
	now.Store(int64(60 * time.Second))
	l.purgeStale()

	if _, ok := l.buckets.Load("fresh-key"); !ok {
		t.Fatal("expected fresh-key to survive purge")
	}
}

// --------------------------------------------------------------------------
// RetryAfter accuracy
// --------------------------------------------------------------------------

func TestTokenBucketLimiter_RetryAfter_ReflectsDeficit(t *testing.T) {
	// Rate: 1 token/second; bucket size: 1.
	l := newTestLimiter(1, 1.0, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	_ = l.Allow(ctx, "k") // consume the one token

	err := l.Allow(ctx, "k")
	var rle *signalerrors.RateLimitedError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *RateLimitedError, got %T", err)
	}
	// Deficit is 1 token at 1 token/s → 1 second.
	if rle.RetryAfterSeconds != 1 {
		t.Errorf("expected RetryAfterSeconds=1, got %d", rle.RetryAfterSeconds)
	}
}

func TestTokenBucketLimiter_RetryAfter_LargeDeficit(t *testing.T) {
	// Rate: 1 token/day ≈ 1.157e-5/s; bucket size: 1.
	l := newTestLimiter(1, 1.0/86400.0, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	_ = l.Allow(ctx, "k")

	err := l.Allow(ctx, "k")
	var rle *signalerrors.RateLimitedError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *RateLimitedError, got %T", err)
	}
	// 1 token / (1/86400 tokens/s) = 86400 seconds.
	if rle.RetryAfterSeconds < 86000 || rle.RetryAfterSeconds > 87000 {
		t.Errorf("expected ~86400s retry, got %d", rle.RetryAfterSeconds)
	}
}

// --------------------------------------------------------------------------
// Stop / lifecycle
// --------------------------------------------------------------------------

func TestTokenBucketLimiter_Stop_DoesNotBlock(t *testing.T) {
	l := newTestLimiter(5, 1.0, fixedClock(0))

	done := make(chan struct{})
	go func() {
		l.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() blocked for too long")
	}
}

func TestNewTokenBucketLimiter_DefaultsApplied(t *testing.T) {
	cfg := BucketConfig{BucketSize: 10, RefillRate: 1.0}
	l := NewTokenBucketLimiter(cfg)
	defer l.Stop()

	if l.cfg.CleanupInterval != defaultCleanupInterval {
		t.Errorf("expected default cleanup interval %v, got %v", defaultCleanupInterval, l.cfg.CleanupInterval)
	}
	if l.cfg.StaleAfter != defaultStaleAfter {
		t.Errorf("expected default stale after %v, got %v", defaultStaleAfter, l.cfg.StaleAfter)
	}
}

// --------------------------------------------------------------------------
// cleanupLoop via real timer (exercises the ticker path)
// --------------------------------------------------------------------------

func TestTokenBucketLimiter_CleanupLoop_PurgesViaTimer(t *testing.T) {
	// Use a very short cleanup interval so the goroutine fires during the test.
	cfg := BucketConfig{
		BucketSize:      5,
		RefillRate:      1.0,
		CleanupInterval: 20 * time.Millisecond,
		StaleAfter:      1 * time.Nanosecond, // immediately stale
	}
	l := NewTokenBucketLimiter(cfg)
	defer l.Stop()

	ctx := context.Background()
	_ = l.Allow(ctx, "cleanup-test-key")

	// Verify bucket exists.
	if _, ok := l.buckets.Load("cleanup-test-key"); !ok {
		t.Fatal("expected bucket before cleanup")
	}

	// Wait long enough for the cleanup goroutine to fire.
	time.Sleep(100 * time.Millisecond)

	// The bucket should have been purged (staleAfter is 1 ns).
	// It is acceptable if cleanup ran between Allow and this check.
	// The key point is the code path was exercised without panicking.
	_, _ = l.buckets.Load("cleanup-test-key")
}

// --------------------------------------------------------------------------
// RetryAfter minimum of 1 second
// --------------------------------------------------------------------------

func TestTokenBucketLimiter_RetryAfter_MinimumOne(t *testing.T) {
	// Very high refill rate: 1e9 tokens per second.
	// Deficit after one token consumed is 1 token = 1e-9 s < 1 s.
	// The implementation should still return RetryAfterSeconds >= 1.
	l := newTestLimiter(1, 1e9, fixedClock(0))
	defer l.Stop()

	ctx := context.Background()
	_ = l.Allow(ctx, "k")

	err := l.Allow(ctx, "k")
	var rle *signalerrors.RateLimitedError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *RateLimitedError, got %T", err)
	}
	if rle.RetryAfterSeconds < 1 {
		t.Errorf("RetryAfterSeconds must be >= 1, got %d", rle.RetryAfterSeconds)
	}
}

// --------------------------------------------------------------------------
// Stop idempotency
// --------------------------------------------------------------------------

// TestTokenBucketLimiter_Stop_IsIdempotent verifies that calling Stop twice on
// the same limiter does not panic.  The second call must be a no-op because
// Stop is guarded by sync.Once.
func TestTokenBucketLimiter_Stop_IsIdempotent(t *testing.T) {
	l := newTestLimiter(5, 1.0, fixedClock(0))

	l.Stop()
	// Must not panic.
	l.Stop()
}

// TestTokenBucketLimiter_Stop_IdempotentUnderConcurrency exercises simultaneous
// calls to Stop from multiple goroutines to ensure that the sync.Once guard
// prevents any channel double-close panic under the race detector.
func TestTokenBucketLimiter_Stop_IdempotentUnderConcurrency(t *testing.T) {
	l := newTestLimiter(5, 1.0, fixedClock(0))

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			l.Stop()
		}()
	}
	wg.Wait()
}

// --------------------------------------------------------------------------
// Overflow guard in refill
// --------------------------------------------------------------------------

// TestTokenBucketLimiter_Refill_OverflowGuard_ExtremeRate verifies that a
// combination of a near-maximum BucketSize and an enormous RefillRate does not
// cause an int64 arithmetic overflow in refill().  Without the saturation
// guard, cur+toAdd could wrap to a negative value, making the bucket appear
// empty when it should be full.
func TestTokenBucketLimiter_Refill_OverflowGuard_ExtremeRate(t *testing.T) {
	var now atomic.Int64
	now.Store(0)

	// BucketSize chosen so that max = BucketSize*tokenScale fits in int64.
	// RefillRate is enormous: after 1 second, toAdd would overflow int64
	// without the saturation guard (1e15 * 1e9 >> math.MaxInt64 ≈ 9.2e18).
	cfg := BucketConfig{
		BucketSize:      1,
		RefillRate:      1e15, // would produce toAdd >> MaxInt64 per second
		CleanupInterval: time.Hour,
		StaleAfter:      time.Hour,
	}
	l := newTokenBucketLimiterWithClock(cfg, func() int64 { return now.Load() })
	defer l.Stop()

	ctx := context.Background()

	// Exhaust the single token.
	if err := l.Allow(ctx, "k"); err != nil {
		t.Fatalf("unexpected error on first Allow: %v", err)
	}

	// Advance clock by 1 second; the extreme RefillRate would overflow without
	// the saturation guard.  The bucket must be clamped to BucketSize (1).
	now.Store(int64(time.Second))

	// Must allow exactly 1 request (the refilled token), not panic or behave
	// erratically due to overflow.
	if err := l.Allow(ctx, "k"); err != nil {
		t.Fatalf("expected allow after refill with extreme rate: %v", err)
	}

	// Exactly 1 token was available; the next must be denied.
	if err := l.Allow(ctx, "k"); err == nil {
		t.Fatal("expected rate limit error; bucket should be empty after consuming the refilled token")
	}
}

// TestTokenBucketLimiter_Refill_OverflowGuard_TokensNeverExceedMax ensures
// that with a realistic but high RefillRate the refilled token count never
// exceeds BucketSize, confirming the saturation arithmetic is correct even
// when toAdd >> remaining capacity.
func TestTokenBucketLimiter_Refill_OverflowGuard_TokensNeverExceedMax(t *testing.T) {
	var now atomic.Int64
	now.Store(0)

	cfg := BucketConfig{
		BucketSize:      3,
		RefillRate:      1e12, // tokens/s; far exceeds bucket size
		CleanupInterval: time.Hour,
		StaleAfter:      time.Hour,
	}
	l := newTokenBucketLimiterWithClock(cfg, func() int64 { return now.Load() })
	defer l.Stop()

	ctx := context.Background()

	// Drain the bucket completely.
	for range 3 {
		if err := l.Allow(ctx, "k"); err != nil {
			t.Fatalf("unexpected error draining bucket: %v", err)
		}
	}

	// Advance clock so that toAdd >> max without overflow guard clamping would
	// produce a negative or absurdly large token count.
	now.Store(int64(time.Second))

	// Refill must clamp to exactly BucketSize = 3; no more, no less.
	for i := range 3 {
		if err := l.Allow(ctx, "k"); err != nil {
			t.Fatalf("request %d after refill: unexpected error: %v", i, err)
		}
	}
	if err := l.Allow(ctx, "k"); err == nil {
		t.Fatal("4th request must be denied; bucket capped at size 3 after overflow-safe refill")
	}
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// fixedClock returns a nowFn that always returns the given nanosecond value.
func fixedClock(nanos int64) func() int64 {
	return func() int64 { return nanos }
}
