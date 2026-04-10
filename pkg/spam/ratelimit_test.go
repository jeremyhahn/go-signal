package spam

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestRateLimitChecker builds a RateLimitChecker with a controllable clock
// so tests do not need to sleep.
func newTestRateLimitChecker(cfg RateLimitConfig, now func() time.Time) *RateLimitChecker {
	r := NewRateLimitChecker(cfg)
	r.nowFn = now
	return r
}

func senderCtx(uuid string) *CheckContext {
	return &CheckContext{
		SenderUUID:    uuid,
		RecipientUUID: "recipient-uuid",
	}
}

func TestRateLimitChecker_AllowsUnderThreshold(t *testing.T) {
	fixed := time.Now()
	checker := newTestRateLimitChecker(RateLimitConfig{
		Window:         time.Minute,
		Threshold:      10,
		ChallengeRatio: 0.8, // challenge at 8
	}, func() time.Time { return fixed })

	// Send 7 messages — all should be allowed (below 80% of 10 = 8).
	for i := 0; i < 7; i++ {
		result, err := checker.Check(context.Background(), senderCtx("alice"))
		if err != nil {
			t.Fatalf("unexpected error on message %d: %v", i+1, err)
		}
		if result != SpamCheckAllow {
			t.Errorf("message %d: expected SpamCheckAllow, got %v", i+1, result)
		}
	}
}

func TestRateLimitChecker_ChallengesAtThreshold(t *testing.T) {
	fixed := time.Now()
	checker := newTestRateLimitChecker(RateLimitConfig{
		Window:         time.Minute,
		Threshold:      10,
		ChallengeRatio: 0.8, // challenge after 8
	}, func() time.Time { return fixed })

	// Send 8 messages to reach the challenge boundary.
	for i := 0; i < 8; i++ {
		checker.Check(context.Background(), senderCtx("bob")) //nolint:errcheck
	}

	// Message 9 (count=9, > challengeAt=8) should be challenged.
	result, err := checker.Check(context.Background(), senderCtx("bob"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != SpamCheckChallenge {
		t.Errorf("expected SpamCheckChallenge at 80%% threshold, got %v", result)
	}
}

func TestRateLimitChecker_BlocksAtThreshold(t *testing.T) {
	fixed := time.Now()
	checker := newTestRateLimitChecker(RateLimitConfig{
		Window:         time.Minute,
		Threshold:      10,
		ChallengeRatio: 0.8,
	}, func() time.Time { return fixed })

	// Send 10 messages to reach the block threshold.
	for i := 0; i < 10; i++ {
		checker.Check(context.Background(), senderCtx("carol")) //nolint:errcheck
	}

	// Message 11 (count=11, > threshold=10) should be blocked.
	result, err := checker.Check(context.Background(), senderCtx("carol"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != SpamCheckBlock {
		t.Errorf("expected SpamCheckBlock after threshold exceeded, got %v", result)
	}
}

func TestRateLimitChecker_ResetsAfterWindow(t *testing.T) {
	start := time.Now()
	current := start

	checker := newTestRateLimitChecker(RateLimitConfig{
		Window:         100 * time.Millisecond,
		Threshold:      5,
		ChallengeRatio: 0.8,
	}, func() time.Time { return current })

	// Exhaust the window.
	for i := 0; i < 6; i++ {
		checker.Check(context.Background(), senderCtx("dave")) //nolint:errcheck
	}
	result, _ := checker.Check(context.Background(), senderCtx("dave"))
	if result != SpamCheckBlock {
		t.Fatalf("expected block before window reset, got %v", result)
	}

	// Advance clock past the window — counter should reset.
	current = start.Add(200 * time.Millisecond)
	result, err := checker.Check(context.Background(), senderCtx("dave"))
	if err != nil {
		t.Fatalf("unexpected error after window reset: %v", err)
	}
	if result != SpamCheckAllow {
		t.Errorf("expected SpamCheckAllow after window reset, got %v", result)
	}
}

func TestRateLimitChecker_IndependentCountersPerSender(t *testing.T) {
	fixed := time.Now()
	checker := newTestRateLimitChecker(RateLimitConfig{
		Window:         time.Minute,
		Threshold:      5,
		ChallengeRatio: 0.8,
	}, func() time.Time { return fixed })

	// Exhaust alice's window.
	for i := 0; i < 6; i++ {
		checker.Check(context.Background(), senderCtx("alice")) //nolint:errcheck
	}
	resultAlice, _ := checker.Check(context.Background(), senderCtx("alice"))
	if resultAlice != SpamCheckBlock {
		t.Fatalf("expected alice to be blocked, got %v", resultAlice)
	}

	// Bob is a different sender; his counter is untouched.
	resultBob, err := checker.Check(context.Background(), senderCtx("bob"))
	if err != nil {
		t.Fatalf("unexpected error for bob: %v", err)
	}
	if resultBob != SpamCheckAllow {
		t.Errorf("expected bob to be allowed, got %v", resultBob)
	}
}

func TestRateLimitChecker_DefaultConfig(t *testing.T) {
	// Zero-value config should use defaults without panicking.
	checker := NewRateLimitChecker(RateLimitConfig{})
	if checker.threshold != DefaultRateLimitThreshold {
		t.Errorf("expected default threshold %d, got %d", DefaultRateLimitThreshold, checker.threshold)
	}
	if checker.window != DefaultRateLimitWindow {
		t.Errorf("expected default window %v, got %v", DefaultRateLimitWindow, checker.window)
	}
}

// TestRateLimitChecker_ConcurrentSafe verifies that no race conditions exist
// when many goroutines send messages for the same and different senders
// simultaneously. The test is intended to be run with -race.
func TestRateLimitChecker_ConcurrentSafe(t *testing.T) {
	fixed := time.Now()
	checker := newTestRateLimitChecker(RateLimitConfig{
		Window:         time.Minute,
		Threshold:      1000,
		ChallengeRatio: 0.8,
	}, func() time.Time { return fixed })

	const goroutines = 50
	const messagesEach = 40

	var wg sync.WaitGroup
	var allowCount, challengeCount, blockCount atomic.Int64

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < messagesEach; i++ {
				result, err := checker.Check(context.Background(), senderCtx("shared-sender"))
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				switch result {
				case SpamCheckAllow:
					allowCount.Add(1)
				case SpamCheckChallenge:
					challengeCount.Add(1)
				case SpamCheckBlock:
					blockCount.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	total := allowCount.Load() + challengeCount.Load() + blockCount.Load()
	if total != goroutines*messagesEach {
		t.Errorf("expected %d total results, got %d", goroutines*messagesEach, total)
	}
}

func TestRateLimitChecker_ImplementsInterface(t *testing.T) {
	var _ SpamChecker = &RateLimitChecker{}
}

// TestRateLimitChecker_StopIdempotent verifies that calling Stop() more than
// once never panics (the underlying sync.Once guarantees this).
func TestRateLimitChecker_StopIdempotent(t *testing.T) {
	checker := NewRateLimitChecker(RateLimitConfig{})
	// First call must not panic.
	checker.Stop()
	// Second call must also not panic.
	checker.Stop()
}

// TestRateLimitChecker_StopBlocksUntilCleanupExits verifies that Stop returns
// only after the background goroutine has fully exited, guarding against use-
// after-free scenarios in callers that tear down the checker on shutdown.
func TestRateLimitChecker_StopBlocksUntilCleanupExits(t *testing.T) {
	checker := NewRateLimitChecker(RateLimitConfig{})
	done := make(chan struct{})
	go func() {
		checker.Stop()
		close(done)
	}()
	select {
	case <-done:
		// expected — Stop returned promptly
	case <-time.After(2 * time.Second):
		t.Fatal("Stop() did not return within 2 seconds")
	}
}

// TestRateLimitChecker_EvictExpired verifies that evictExpired removes sender
// entries whose windows have already elapsed and leaves entries whose windows
// are still active.
func TestRateLimitChecker_EvictExpired(t *testing.T) {
	start := time.Now()
	current := start

	checker := newTestRateLimitChecker(RateLimitConfig{
		Window:    100 * time.Millisecond,
		Threshold: 10,
	}, func() time.Time { return current })
	defer checker.Stop()

	// Seed two senders while the window is active.
	checker.Check(context.Background(), senderCtx("evict-alice")) //nolint:errcheck
	checker.Check(context.Background(), senderCtx("evict-bob"))   //nolint:errcheck

	// Advance time past the window so both entries are stale.
	current = start.Add(200 * time.Millisecond)
	checker.evictExpired()

	checker.mu.RLock()
	remaining := len(checker.senders)
	checker.mu.RUnlock()

	if remaining != 0 {
		t.Errorf("expected 0 senders after eviction, got %d", remaining)
	}
}

// TestRateLimitChecker_EvictExpiredKeepsActiveEntries ensures that a sender
// whose window is still valid is not removed by evictExpired.
func TestRateLimitChecker_EvictExpiredKeepsActiveEntries(t *testing.T) {
	fixed := time.Now()
	checker := newTestRateLimitChecker(RateLimitConfig{
		Window:    time.Minute,
		Threshold: 10,
	}, func() time.Time { return fixed })
	defer checker.Stop()

	checker.Check(context.Background(), senderCtx("active-sender")) //nolint:errcheck
	checker.evictExpired()

	checker.mu.RLock()
	remaining := len(checker.senders)
	checker.mu.RUnlock()

	if remaining != 1 {
		t.Errorf("expected active sender to survive eviction, got %d senders", remaining)
	}
}

// TestRateLimitChecker_ConcurrentWindowBoundary launches many goroutines that
// all call Check at exactly the window boundary. It verifies that no panics
// occur and that every call returns a valid result. The test is run with -race
// to surface any residual data races.
func TestRateLimitChecker_ConcurrentWindowBoundary(t *testing.T) {
	start := time.Now()
	var currentNano atomic.Int64
	currentNano.Store(start.UnixNano())

	checker := newTestRateLimitChecker(RateLimitConfig{
		Window:    50 * time.Millisecond,
		Threshold: 1000,
	}, func() time.Time {
		return time.Unix(0, currentNano.Load())
	})
	defer checker.Stop()

	// Warm up: send one message so the window is initialised.
	checker.Check(context.Background(), senderCtx("boundary-sender")) //nolint:errcheck

	// Atomically advance the clock to exactly the window boundary so all
	// goroutines observe an expired window on their first read.
	expiredTime := start.Add(100 * time.Millisecond)
	currentNano.Store(expiredTime.UnixNano())

	const goroutines = 100
	var wg sync.WaitGroup
	results := make([]SpamCheckResult, goroutines)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			result, err := checker.Check(context.Background(), senderCtx("boundary-sender"))
			if err != nil {
				t.Errorf("goroutine %d: unexpected error: %v", idx, err)
				return
			}
			results[idx] = result
		}(g)
	}
	wg.Wait()

	// Every goroutine must have received a well-defined result.
	for i, r := range results {
		if r != SpamCheckAllow && r != SpamCheckChallenge && r != SpamCheckBlock {
			t.Errorf("goroutine %d: invalid result %v", i, r)
		}
	}
}

// TestRateLimitChecker_IncrementLoserDoesNotLoseCount verifies that when the
// CAS inside increment() fails (loser path), the goroutine re-reads the new
// window and still records its increment — i.e., no message is silently
// dropped due to the TOCTOU fix.
func TestRateLimitChecker_IncrementLoserDoesNotLoseCount(t *testing.T) {
	start := time.Now()
	var currentNano atomic.Int64
	currentNano.Store(start.UnixNano())

	checker := newTestRateLimitChecker(RateLimitConfig{
		Window:    50 * time.Millisecond,
		Threshold: 10000,
	}, func() time.Time {
		return time.Unix(0, currentNano.Load())
	})
	defer checker.Stop()

	// Initialise the sender entry.
	checker.Check(context.Background(), senderCtx("loser-sender")) //nolint:errcheck

	// Advance clock past window so all goroutines race to reset it.
	currentNano.Store(start.Add(100 * time.Millisecond).UnixNano())

	const goroutines = 50
	var wg sync.WaitGroup
	var totalCount atomic.Int64

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := checker.Check(context.Background(), senderCtx("loser-sender"))
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			totalCount.Add(1)
		}()
	}
	wg.Wait()

	// All goroutines completed successfully; verify the stored count equals
	// the number of goroutines (every increment was applied).
	checker.mu.RLock()
	c := checker.senders["loser-sender"]
	checker.mu.RUnlock()

	stored := c.count.Load()
	if stored != goroutines {
		t.Errorf("expected stored count %d, got %d — some increments were lost", goroutines, stored)
	}
}
