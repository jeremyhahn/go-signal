package spam

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimitConfig holds the tunable parameters for RateLimitChecker.
type RateLimitConfig struct {
	// Window is the duration of the rolling time window used to count messages
	// per sender. Zero uses DefaultRateLimitWindow.
	Window time.Duration

	// Threshold is the maximum number of messages a sender may send within
	// Window before being blocked. Zero uses DefaultRateLimitThreshold.
	Threshold int64

	// ChallengeRatio is the fraction of Threshold at which the checker begins
	// returning SpamCheckChallenge instead of SpamCheckAllow. For example,
	// 0.8 means challenge starts at 80 % of Threshold. Zero uses
	// DefaultChallengeRatio.
	ChallengeRatio float64
}

const (
	// DefaultRateLimitWindow is the rolling window used when none is specified.
	DefaultRateLimitWindow = time.Minute

	// DefaultRateLimitThreshold is the per-sender message cap per window.
	DefaultRateLimitThreshold int64 = 100

	// DefaultChallengeRatio is the fraction of the threshold at which
	// challenge mode begins (80 %).
	DefaultChallengeRatio float64 = 0.8

	// cleanupInterval is how often the background goroutine evicts expired
	// sender entries from the map.
	cleanupInterval = 60 * time.Second
)

// senderCounter tracks the message count and window expiry for a single sender
// using atomic operations so that the hot path (incrementing the counter)
// requires no mutex.
type senderCounter struct {
	// count is the number of messages sent in the current window.
	count atomic.Int64

	// windowEnd is the Unix nanosecond timestamp at which the current window
	// expires, stored as int64 for atomic access.
	windowEnd atomic.Int64
}

// RateLimitChecker is a SpamChecker that tracks per-sender message rates using
// a fixed time window. It uses lock-free atomic counters for the hot increment
// path; a single RWMutex protects the sender map only for entry creation and
// eviction, not for per-message updates.
//
// When a sender's message count within the window exceeds ChallengeRatio *
// Threshold, SpamCheckChallenge is returned. When it exceeds Threshold,
// SpamCheckBlock is returned.
//
// A background goroutine periodically evicts entries whose windows have
// expired, bounding the memory consumed by the sender map. Call Stop() to
// shut it down cleanly.
type RateLimitChecker struct {
	window      time.Duration
	threshold   int64
	challengeAt int64 // floor(threshold * challengeRatio)
	mu          sync.RWMutex
	senders     map[string]*senderCounter
	nowFn       func() time.Time // injectable for testing

	stopCleanup chan struct{}
	cleanupDone chan struct{}
	stopOnce    sync.Once
}

// NewRateLimitChecker constructs a RateLimitChecker with the provided config.
// Zero-value fields in cfg are replaced with their defaults. The returned
// checker starts a background cleanup goroutine; call Stop() when the checker
// is no longer needed to release its resources.
func NewRateLimitChecker(cfg RateLimitConfig) *RateLimitChecker {
	if cfg.Window <= 0 {
		cfg.Window = DefaultRateLimitWindow
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = DefaultRateLimitThreshold
	}
	if cfg.ChallengeRatio <= 0 {
		cfg.ChallengeRatio = DefaultChallengeRatio
	}
	challengeAt := int64(float64(cfg.Threshold) * cfg.ChallengeRatio)
	if challengeAt < 1 {
		challengeAt = 1
	}

	r := &RateLimitChecker{
		window:      cfg.Window,
		threshold:   cfg.Threshold,
		challengeAt: challengeAt,
		senders:     make(map[string]*senderCounter),
		nowFn:       time.Now,
		stopCleanup: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	go r.cleanupLoop()
	return r
}

// Stop shuts down the background cleanup goroutine and waits for it to exit.
// It is safe to call Stop more than once; subsequent calls are no-ops.
func (r *RateLimitChecker) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopCleanup)
		<-r.cleanupDone
	})
}

// Check increments the per-sender message counter and returns:
//   - SpamCheckBlock     when count > Threshold
//   - SpamCheckChallenge when count > challengeAt (80% of Threshold by default)
//   - SpamCheckAllow     otherwise
func (r *RateLimitChecker) Check(_ context.Context, checkCtx *CheckContext) (SpamCheckResult, error) {
	now := r.nowFn()
	counter := r.getOrCreate(checkCtx.SenderUUID)
	count := r.increment(counter, now)

	switch {
	case count > r.threshold:
		return SpamCheckBlock, nil
	case count > r.challengeAt:
		return SpamCheckChallenge, nil
	default:
		return SpamCheckAllow, nil
	}
}

// getOrCreate returns the senderCounter for uuid, creating it if necessary.
// Creation uses a double-checked lock to minimise contention.
func (r *RateLimitChecker) getOrCreate(uuid string) *senderCounter {
	r.mu.RLock()
	c, ok := r.senders[uuid]
	r.mu.RUnlock()
	if ok {
		return c
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Re-check under write lock to avoid a race with a concurrent creator.
	if c, ok = r.senders[uuid]; ok {
		return c
	}
	c = &senderCounter{}
	r.senders[uuid] = c
	return c
}

// increment atomically updates the counter for the current window, resetting
// the window if it has expired. It returns the new count.
//
// The implementation uses a CAS loop to eliminate the TOCTOU race present in
// a simple load-then-CAS pattern: a goroutine that loses the CAS race (i.e.,
// another goroutine has already reset the window) re-reads the current window
// end and retries, guaranteeing it always increments within the correct window.
func (r *RateLimitChecker) increment(c *senderCounter, now time.Time) int64 {
	nowNano := now.UnixNano()
	for {
		windowEndNano := c.windowEnd.Load()
		if nowNano < windowEndNano {
			// Window is still active; atomically increment and return.
			return c.count.Add(1)
		}

		// Window has expired. Race to claim the reset.
		newWindowEnd := now.Add(r.window).UnixNano()
		if c.windowEnd.CompareAndSwap(windowEndNano, newWindowEnd) {
			// Winner: reset the counter to 1; this message opens the window.
			c.count.Store(1)
			return 1
		}
		// Loser: another goroutine has already reset the window. Re-read and
		// retry so we increment within the new window, not the expired one.
	}
}

// cleanupLoop runs in a background goroutine and calls evictExpired on every
// tick until Stop is called.
func (r *RateLimitChecker) cleanupLoop() {
	defer close(r.cleanupDone)
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCleanup:
			return
		case <-ticker.C:
			r.evictExpired()
		}
	}
}

// evictExpired removes all senderCounter entries whose windows have already
// expired. It acquires the write lock for the duration of the map scan.
func (r *RateLimitChecker) evictExpired() {
	now := r.nowFn().UnixNano()
	r.mu.Lock()
	defer r.mu.Unlock()
	for uuid, c := range r.senders {
		if now >= c.windowEnd.Load() {
			delete(r.senders, uuid)
		}
	}
}
