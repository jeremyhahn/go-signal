package spam

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// RegistrationFraudChecker evaluates registration requests for fraud signals.
// Implementations must be safe for concurrent use.
type RegistrationFraudChecker interface {
	// Check evaluates a registration attempt and returns true if the request
	// appears fraudulent and should be blocked.
	Check(ctx context.Context, req *RegistrationFraudRequest) bool
}

// RegistrationFraudRequest holds the contextual data available at registration
// time for fraud scoring.
type RegistrationFraudRequest struct {
	// IP is the remote address of the registering client.
	IP string
	// PhoneNumber is the phone number being registered.
	PhoneNumber string
	// UserAgent is the User-Agent header value.
	UserAgent string
	// Timestamp is the server-side time of the request.
	Timestamp time.Time
}

// FraudCheckerConfig holds configuration for DefaultFraudChecker.
type FraudCheckerConfig struct {
	// MaxRegistrationsPerIP is the maximum registrations allowed per IP
	// within the tracking window. Zero uses the default (10).
	MaxRegistrationsPerIP int
	// MaxRegistrationsPerPrefix is the maximum registrations allowed per
	// phone number prefix (first 4 digits) within the tracking window.
	// Zero uses the default (50).
	MaxRegistrationsPerPrefix int
	// Window is the time window for velocity tracking. Zero uses the
	// default (1 hour).
	Window time.Duration
}

// velocityEntry tracks request count and window start for a single key.
type velocityEntry struct {
	count       atomic.Int64
	windowStart atomic.Int64 // unix nanoseconds
}

// fraudCleanupInterval is the period between background eviction passes.
const fraudCleanupInterval = 60 * time.Second

// DefaultFraudChecker implements RegistrationFraudChecker with heuristic
// scoring based on registration velocity per IP and phone number prefix
// patterns.
//
// A background goroutine evicts expired entries every fraudCleanupInterval.
// Call Stop to release resources; Stop is idempotent.
type DefaultFraudChecker struct {
	// maxPerIP is the maximum registrations allowed per IP within the window.
	maxPerIP int
	// maxPerPrefix is the maximum registrations per phone prefix within the window.
	maxPerPrefix int
	// window is the time window for velocity tracking.
	window time.Duration
	// ipCounts tracks registration counts per IP.
	ipCounts sync.Map
	// prefixCounts tracks registration counts per phone prefix.
	prefixCounts sync.Map
	// stopCh is closed to signal the cleanup goroutine to exit.
	stopCh chan struct{}
	// doneCh is closed by the cleanup goroutine after it exits.
	doneCh chan struct{}
	// stopOnce ensures Stop's close(stopCh) runs exactly once.
	stopOnce sync.Once
}

// NewDefaultFraudChecker creates a DefaultFraudChecker with the given config
// and starts a background cleanup goroutine. Call Stop when done.
func NewDefaultFraudChecker(cfg FraudCheckerConfig) *DefaultFraudChecker {
	maxIP := cfg.MaxRegistrationsPerIP
	if maxIP <= 0 {
		maxIP = 10
	}
	maxPrefix := cfg.MaxRegistrationsPerPrefix
	if maxPrefix <= 0 {
		maxPrefix = 50
	}
	window := cfg.Window
	if window <= 0 {
		window = time.Hour
	}
	fc := &DefaultFraudChecker{
		maxPerIP:     maxIP,
		maxPerPrefix: maxPrefix,
		window:       window,
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
	go fc.cleanupLoop()
	return fc
}

// Stop halts the background cleanup goroutine and waits for it to exit.
// It is safe to call Stop more than once; subsequent calls are no-ops.
func (c *DefaultFraudChecker) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
		<-c.doneCh
	})
}

// cleanupLoop runs until stopCh is closed, evicting expired entries on each tick.
func (c *DefaultFraudChecker) cleanupLoop() {
	defer close(c.doneCh)
	ticker := time.NewTicker(fraudCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.evictExpired()
		}
	}
}

// evictExpired deletes entries whose tracking window has elapsed from both
// ipCounts and prefixCounts.
func (c *DefaultFraudChecker) evictExpired() {
	now := time.Now().UnixNano()
	evict := func(m *sync.Map) {
		m.Range(func(key, value any) bool {
			entry, ok := value.(*velocityEntry)
			if !ok {
				// Only *velocityEntry is ever stored; leave anything else alone.
				return true
			}
			if now-entry.windowStart.Load() > c.window.Nanoseconds() {
				m.Delete(key)
			}
			return true
		})
	}
	evict(&c.ipCounts)
	evict(&c.prefixCounts)
}

// Check evaluates the registration request against velocity heuristics.
// Returns true if the request appears fraudulent.
func (c *DefaultFraudChecker) Check(_ context.Context, req *RegistrationFraudRequest) bool {
	if req == nil {
		return false
	}

	// Check IP velocity.
	if req.IP != "" && c.incrementAndCheck(&c.ipCounts, req.IP, c.maxPerIP, req.Timestamp) {
		return true
	}

	// Check phone prefix velocity (first 4 characters).
	prefix := phonePrefix(req.PhoneNumber)
	if prefix != "" && c.incrementAndCheck(&c.prefixCounts, prefix, c.maxPerPrefix, req.Timestamp) {
		return true
	}

	return false
}

// incrementAndCheck atomically increments the counter for key and returns
// true if the count exceeds maxCount within the configured window.
//
// A CAS loop on windowStart ensures that exactly one goroutine wins the window
// reset race. The winner stores count=1 and returns false (not fraudulent).
// Every losing goroutine re-reads the (now-fresh) windowStart and falls through
// to the active-window Add(1) path, preserving an accurate request count.
func (c *DefaultFraudChecker) incrementAndCheck(m *sync.Map, key string, maxCount int, now time.Time) bool {
	nowNano := now.UnixNano()
	val, _ := m.LoadOrStore(key, &velocityEntry{})
	entry, ok := val.(*velocityEntry)
	if !ok {
		// Only *velocityEntry is ever stored; anything else carries no signal.
		return false
	}

	for {
		windowStart := entry.windowStart.Load()
		if nowNano-windowStart > c.window.Nanoseconds() {
			// Window has expired. Race to claim the reset via CAS.
			if entry.windowStart.CompareAndSwap(windowStart, nowNano) {
				// CAS winner: reset the counter to 1 (this request).
				entry.count.Store(1)
				return false
			}
			// CAS loser: another goroutine already reset the window.
			// Loop to re-read windowStart and take the active-window path.
			continue
		}
		// Window is still active; atomically increment and evaluate.
		count := entry.count.Add(1)
		return count > int64(maxCount)
	}
}

// phonePrefix extracts the first 4 characters of a phone number for prefix
// grouping. Returns empty string if the number is too short.
func phonePrefix(number string) string {
	if len(number) < 4 {
		return ""
	}
	return number[:4]
}

// NoOpFraudChecker always allows registrations. Used when no fraud detection
// policy is configured.
type NoOpFraudChecker struct{}

// Check always returns false (not fraudulent).
func (NoOpFraudChecker) Check(_ context.Context, _ *RegistrationFraudRequest) bool {
	return false
}
