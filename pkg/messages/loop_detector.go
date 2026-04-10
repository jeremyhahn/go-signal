package messages

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// maxGUIDsPerEntry caps the number of GUIDs tracked per directed entry within
// a single window. Once the cap is reached, new GUIDs for that direction are
// silently dropped to prevent unbounded memory growth under a sustained flood.
const maxGUIDsPerEntry = 10_000

// DeliveryLoopError indicates that a delivery loop has been detected between
// two accounts: the same message GUID has been observed travelling in both
// directions within the configured time window.
type DeliveryLoopError struct {
	SenderUUID    string
	RecipientUUID string
	MessageGUID   string
}

func (e *DeliveryLoopError) Error() string {
	return "delivery loop detected: " + e.SenderUUID + " -> " + e.RecipientUUID + " guid=" + e.MessageGUID
}

// pairKey produces a canonical, direction-agnostic key for a sender-recipient
// pair. The lexicographically smaller UUID is always placed first so that
// A->B and B->A share the same pair key.
func pairKey(a, b string) string {
	if a <= b {
		return a + "\x00" + b
	}
	return b + "\x00" + a
}

// directedEntry tracks one observed message direction (sender->recipient) and
// the set of GUIDs that have been sent in that direction within the window.
type directedEntry struct {
	// sender is stored so the detector can distinguish which direction an entry
	// was recorded in (A->B vs B->A for the same pair key).
	sender    string
	guids     map[string]struct{}
	expiresAt int64 // UnixNano
}

// loopBucket holds all direction-entries for a sender-recipient pair.
type loopBucket struct {
	mu      sync.Mutex
	entries []*directedEntry
}

// DeliveryLoopDetector tracks message-delivery paths using a bounded per-pair
// entry set with TTL-based expiry. It detects loops where the same message
// GUID is sent A->B and then B->A (or vice versa) within windowSize.
//
// All public methods are safe for concurrent use. Internal state is protected
// by per-bucket mutexes to minimise lock contention across different pairs.
type DeliveryLoopDetector struct {
	windowSize     time.Duration
	maxChainLength int
	nowFn          func() int64 // returns UnixNano; injectable for testing

	mu      sync.RWMutex
	buckets map[string]*loopBucket

	// stopped is set to 1 when Stop has been called.
	stopped atomic.Int32
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewDeliveryLoopDetector creates a DeliveryLoopDetector with the given window
// size and maximum chain length. windowSize is the TTL for tracked message
// paths; maxChainLength is the maximum number of back-and-forth hops that
// triggers detection (must be >= 1; values < 1 are treated as 1).
//
// A background goroutine runs periodic cleanup to evict expired entries.
// Call Stop to release resources.
func NewDeliveryLoopDetector(windowSize time.Duration, maxChainLength int) *DeliveryLoopDetector {
	if maxChainLength < 1 {
		maxChainLength = 1
	}
	d := &DeliveryLoopDetector{
		windowSize:     windowSize,
		maxChainLength: maxChainLength,
		nowFn:          func() int64 { return time.Now().UnixNano() },
		buckets:        make(map[string]*loopBucket),
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
	}
	go d.cleanupLoop()
	return d
}

// newDeliveryLoopDetectorWithClock creates a detector with an injectable clock
// for deterministic testing.
func newDeliveryLoopDetectorWithClock(windowSize time.Duration, maxChainLength int, nowFn func() int64) *DeliveryLoopDetector {
	if maxChainLength < 1 {
		maxChainLength = 1
	}
	d := &DeliveryLoopDetector{
		windowSize:     windowSize,
		maxChainLength: maxChainLength,
		nowFn:          nowFn,
		buckets:        make(map[string]*loopBucket),
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
	}
	go d.cleanupLoop()
	return d
}

// Stop halts the background cleanup goroutine and waits for it to exit.
func (d *DeliveryLoopDetector) Stop() {
	if d.stopped.CompareAndSwap(0, 1) {
		close(d.stopCh)
		<-d.doneCh
	}
}

// Check inspects whether recording senderUUID -> recipientUUID for messageGUID
// would constitute a loop (i.e. the same GUID was already recorded travelling
// in the opposite direction within the window). Returns *DeliveryLoopError
// when a loop is detected; nil otherwise.
//
// Check does NOT record the path — callers should call Record separately after
// a successful check to keep the two operations independently testable.
func (d *DeliveryLoopDetector) Check(_ context.Context, senderUUID, recipientUUID, messageGUID string) error {
	key := pairKey(senderUUID, recipientUUID)
	now := d.nowFn()

	d.mu.RLock()
	b, exists := d.buckets[key]
	d.mu.RUnlock()

	if !exists {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Look for live entries recorded in the OPPOSITE direction that carry this GUID.
	for _, entry := range b.entries {
		if entry.expiresAt <= now {
			continue // expired; will be purged by cleanup
		}
		// Opposite direction: entry was sent by the current recipient (to current sender).
		if entry.sender == recipientUUID {
			if _, seen := entry.guids[messageGUID]; seen {
				return &DeliveryLoopError{
					SenderUUID:    senderUUID,
					RecipientUUID: recipientUUID,
					MessageGUID:   messageGUID,
				}
			}
		}
	}

	return nil
}

// Record registers that senderUUID sent a message identified by messageGUID to
// recipientUUID. Existing entries for the same direction are merged (the GUID
// is added to the current live window entry). Expired entries are pruned before
// adding the new record to bound memory usage.
func (d *DeliveryLoopDetector) Record(_ context.Context, senderUUID, recipientUUID, messageGUID string) {
	key := pairKey(senderUUID, recipientUUID)
	now := d.nowFn()
	expiry := now + d.windowSize.Nanoseconds()

	b := d.getOrCreateBucket(key)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Prune expired entries.
	live := b.entries[:0]
	for _, e := range b.entries {
		if e.expiresAt > now {
			live = append(live, e)
		}
	}
	b.entries = live

	// Find an existing live entry for this direction and merge.
	for _, entry := range b.entries {
		if entry.sender == senderUUID {
			if len(entry.guids) < maxGUIDsPerEntry {
				entry.guids[messageGUID] = struct{}{}
			}
			// Extend expiry to the latest observation.
			if expiry > entry.expiresAt {
				entry.expiresAt = expiry
			}
			return
		}
	}

	// No existing live entry for this direction; create one.
	b.entries = append(b.entries, &directedEntry{
		sender:    senderUUID,
		guids:     map[string]struct{}{messageGUID: {}},
		expiresAt: expiry,
	})
}

// getOrCreateBucket returns the bucket for key, creating it atomically when
// necessary.
func (d *DeliveryLoopDetector) getOrCreateBucket(key string) *loopBucket {
	d.mu.RLock()
	b, exists := d.buckets[key]
	d.mu.RUnlock()
	if exists {
		return b
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	// Double-checked locking.
	if b, exists = d.buckets[key]; exists {
		return b
	}
	b = &loopBucket{}
	d.buckets[key] = b
	return b
}

// cleanupLoop periodically removes expired entries and empty buckets to
// prevent unbounded memory growth.
func (d *DeliveryLoopDetector) cleanupLoop() {
	defer close(d.doneCh)

	// Cleanup interval is one-quarter of the window size, with a floor of
	// one second and a ceiling of one minute.
	interval := d.windowSize / 4
	if interval < time.Second {
		interval = time.Second
	}
	if interval > time.Minute {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.purgeExpired()
		}
	}
}

// purgeExpired removes all expired entries from every bucket and removes
// empty buckets from the map.
func (d *DeliveryLoopDetector) purgeExpired() {
	now := d.nowFn()

	d.mu.RLock()
	keys := make([]string, 0, len(d.buckets))
	for k := range d.buckets {
		keys = append(keys, k)
	}
	d.mu.RUnlock()

	for _, key := range keys {
		d.mu.RLock()
		b, exists := d.buckets[key]
		d.mu.RUnlock()
		if !exists {
			continue
		}

		b.mu.Lock()
		live := b.entries[:0]
		for _, e := range b.entries {
			if e.expiresAt > now {
				live = append(live, e)
			}
		}
		b.entries = live
		empty := len(b.entries) == 0
		b.mu.Unlock()

		if empty {
			d.mu.Lock()
			// Re-check under write lock before deleting.
			b2, still := d.buckets[key]
			if still && b2 == b {
				b.mu.Lock()
				if len(b.entries) == 0 {
					delete(d.buckets, key)
				}
				b.mu.Unlock()
			}
			d.mu.Unlock()
		}
	}
}
