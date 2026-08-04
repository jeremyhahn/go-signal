package calling

import (
	"errors"
	"sync"
	"time"
)

// breakerState is the lifecycle of a CircuitBreaker. We use the same
// closed → open → half-open progression as gobreaker / Hystrix but
// implement it directly so we don't take the dependency.
type breakerState int

const (
	breakerClosed   breakerState = iota // normal operation; calls pass through
	breakerOpen                         // tripped; calls short-circuit until the cool-down expires
	breakerHalfOpen                     // probing; one call is allowed through to test recovery
)

// CircuitBreakerConfig parameterizes a CircuitBreaker. Zero-value fields
// take sensible defaults so callers can construct an empty config to get
// the production-default behavior.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures that flip
	// the breaker from closed to open. Defaults to 5.
	FailureThreshold int
	// OpenTimeout is how long the breaker stays open before transitioning
	// to half-open. Defaults to 30s.
	OpenTimeout time.Duration
}

// CircuitBreaker guards an unreliable downstream (Cloudflare TURN here).
// Once FailureThreshold consecutive calls fail, the breaker opens and
// short-circuits subsequent calls with ErrCircuitOpen until OpenTimeout
// elapses. The next call then runs as a half-open probe — success closes
// the breaker; failure re-opens it for another OpenTimeout window.
//
// Safe for concurrent use. State changes are guarded by a single mutex
// since the typical call rate against TURN credentials is < 100/s and
// the lock window is small.
type CircuitBreaker struct {
	mu                  sync.Mutex
	state               breakerState
	consecutiveFailures int
	openedAt            time.Time
	failureThreshold    int
	openTimeout         time.Duration
	now                 func() time.Time
}

// ErrCircuitOpen is returned by Do when the breaker is open and the call
// is short-circuited without invoking fn. Callers can errors.Is this to
// distinguish a breaker-skipped call from an underlying failure.
var ErrCircuitOpen = errors.New("calling: circuit breaker open")

// NewCircuitBreaker returns a fresh breaker. Zero-value config picks the
// production defaults (5 consecutive failures, 30s open window).
func NewCircuitBreaker(cfg CircuitBreakerConfig) *CircuitBreaker {
	failureThreshold := cfg.FailureThreshold
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	openTimeout := cfg.OpenTimeout
	if openTimeout <= 0 {
		openTimeout = 30 * time.Second
	}
	return &CircuitBreaker{
		state:            breakerClosed,
		failureThreshold: failureThreshold,
		openTimeout:      openTimeout,
		now:              time.Now,
	}
}

// Do invokes fn under the breaker's protection. When the breaker is open
// and the cool-down has not elapsed, returns ErrCircuitOpen without
// calling fn. Otherwise, fn's error (or nil) drives the state transitions.
func (b *CircuitBreaker) Do(fn func() error) error {
	if !b.allow() {
		return ErrCircuitOpen
	}
	err := fn()
	b.record(err)
	return err
}

// allow returns true when a call should be attempted. When the breaker
// is open, it auto-promotes to half-open after the cool-down so a single
// probe runs through. Mutates state, so callers must check the return.
func (b *CircuitBreaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case breakerClosed:
		return true
	case breakerOpen:
		if b.now().Sub(b.openedAt) >= b.openTimeout {
			b.state = breakerHalfOpen
			return true
		}
		return false
	case breakerHalfOpen:
		// While a probe is in flight, additional callers short-circuit.
		// In practice with our serialized usage there is no concurrent
		// probe, but the guard keeps the contract conservative.
		return false
	}
	return false
}

// record updates breaker state based on the outcome of the last call.
func (b *CircuitBreaker) record(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.consecutiveFailures++
		if b.state == breakerHalfOpen || b.consecutiveFailures >= b.failureThreshold {
			b.state = breakerOpen
			b.openedAt = b.now()
		}
		return
	}
	// Success: snap state back to closed and reset the counter.
	b.consecutiveFailures = 0
	b.state = breakerClosed
}

// state exposes the current breaker state for tests. Lower-case alias
// for the breakerState ints; not part of the public API.
func (b *CircuitBreaker) currentState() breakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}
