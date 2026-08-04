package calling

import (
	"errors"
	"testing"
	"time"
)

// fakeClock returns a func that advances by the amounts the test
// schedules via Advance, so breaker timing logic can be exercised without
// real-time waits.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }
func (c *fakeClock) Now() time.Time          { return c.now }

func newTestBreaker(threshold int, openTimeout time.Duration) (*CircuitBreaker, *fakeClock) {
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	b := NewCircuitBreaker(CircuitBreakerConfig{
		FailureThreshold: threshold,
		OpenTimeout:      openTimeout,
	})
	b.now = clk.Now
	return b, clk
}

var errFlaky = errors.New("flaky")

func TestNewCircuitBreaker_DefaultsApplied(t *testing.T) {
	b := NewCircuitBreaker(CircuitBreakerConfig{})
	if b.failureThreshold != 5 {
		t.Errorf("failureThreshold default = %d", b.failureThreshold)
	}
	if b.openTimeout != 30*time.Second {
		t.Errorf("openTimeout default = %v", b.openTimeout)
	}
}

func TestBreaker_PassesCallsWhileClosed(t *testing.T) {
	b, _ := newTestBreaker(3, time.Second)
	calls := 0
	for i := 0; i < 5; i++ {
		err := b.Do(func() error {
			calls++
			return nil
		})
		if err != nil {
			t.Fatalf("Do[%d]: %v", i, err)
		}
	}
	if calls != 5 {
		t.Errorf("expected 5 successful calls, got %d", calls)
	}
	if b.currentState() != breakerClosed {
		t.Errorf("expected closed state, got %d", b.currentState())
	}
}

func TestBreaker_OpensAfterThresholdFailures(t *testing.T) {
	b, _ := newTestBreaker(3, time.Second)
	for i := 0; i < 3; i++ {
		_ = b.Do(func() error { return errFlaky })
	}
	if got := b.currentState(); got != breakerOpen {
		t.Fatalf("expected open after 3 failures, got %d", got)
	}
	// Next call short-circuits with ErrCircuitOpen.
	called := false
	err := b.Do(func() error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrCircuitOpen) {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}
	if called {
		t.Error("fn must not be invoked when breaker open")
	}
}

func TestBreaker_HalfOpenProbeSuccess_ClosesBreaker(t *testing.T) {
	b, clk := newTestBreaker(2, 100*time.Millisecond)
	_ = b.Do(func() error { return errFlaky })
	_ = b.Do(func() error { return errFlaky })
	if b.currentState() != breakerOpen {
		t.Fatalf("expected open, got %d", b.currentState())
	}
	// Advance past the open window so the next call probes.
	clk.Advance(200 * time.Millisecond)
	if err := b.Do(func() error { return nil }); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if got := b.currentState(); got != breakerClosed {
		t.Errorf("expected closed after successful probe, got %d", got)
	}
}

func TestBreaker_HalfOpenProbeFailure_ReopensBreaker(t *testing.T) {
	b, clk := newTestBreaker(2, 100*time.Millisecond)
	_ = b.Do(func() error { return errFlaky })
	_ = b.Do(func() error { return errFlaky })
	clk.Advance(200 * time.Millisecond)
	// Probe fails — breaker must re-open and start a new open window.
	if err := b.Do(func() error { return errFlaky }); err == nil {
		t.Fatalf("expected fn error to propagate")
	}
	if got := b.currentState(); got != breakerOpen {
		t.Errorf("expected open after failed probe, got %d", got)
	}
}

func TestBreaker_SuccessResetsConsecutiveFailureCount(t *testing.T) {
	b, _ := newTestBreaker(3, time.Second)
	_ = b.Do(func() error { return errFlaky })
	_ = b.Do(func() error { return errFlaky })
	// A success between failures must reset the counter so the breaker
	// doesn't trip on a non-consecutive third failure.
	_ = b.Do(func() error { return nil })
	_ = b.Do(func() error { return errFlaky })
	if got := b.currentState(); got != breakerClosed {
		t.Errorf("expected breaker still closed, got %d", got)
	}
}

func TestBreaker_ErrCircuitOpenStringStable(t *testing.T) {
	// The error string is part of the operator UX; guard against drift.
	if got := ErrCircuitOpen.Error(); got != "calling: circuit breaker open" {
		t.Errorf("ErrCircuitOpen.Error() = %q", got)
	}
}
