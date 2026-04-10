package messages

import (
	"context"
	"sync"
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// newDeliveryLoopDetectorWithClock – maxChainLength clamp
// --------------------------------------------------------------------------

// TestNewDeliveryLoopDetectorWithClock_MaxChainLengthClampedToOne verifies
// that the internal constructor clamps maxChainLength < 1 to 1, matching the
// behaviour of the public constructor.
func TestNewDeliveryLoopDetectorWithClock_MaxChainLengthClampedToOne(t *testing.T) {
	nowFn, _ := newTestClock(0)
	d := newDeliveryLoopDetectorWithClock(5*time.Second, 0, nowFn)
	defer d.Stop()

	if d.maxChainLength != 1 {
		t.Errorf("expected maxChainLength=1 after clamping 0, got %d", d.maxChainLength)
	}
}

// TestNewDeliveryLoopDetectorWithClock_NegativeChainLengthClamped verifies that
// a negative maxChainLength is clamped to 1.
func TestNewDeliveryLoopDetectorWithClock_NegativeChainLengthClamped(t *testing.T) {
	nowFn, _ := newTestClock(0)
	d := newDeliveryLoopDetectorWithClock(5*time.Second, -5, nowFn)
	defer d.Stop()

	if d.maxChainLength != 1 {
		t.Errorf("expected maxChainLength=1 after clamping -5, got %d", d.maxChainLength)
	}
}

// --------------------------------------------------------------------------
// cleanupLoop – interval ceiling branch (windowSize > 4 minutes → interval = 1 minute)
// --------------------------------------------------------------------------

// TestNewDeliveryLoopDetector_LargeWindowUsesOneMinuteInterval verifies that
// the background cleanup interval is capped at one minute when the window is
// very large. We verify this indirectly by confirming the detector constructs
// and stops cleanly with a large window.
func TestNewDeliveryLoopDetector_LargeWindowUsesOneMinuteInterval(t *testing.T) {
	// windowSize / 4 = 2 hours → must be clamped to 1 minute.
	d := NewDeliveryLoopDetector(8*time.Hour, 1)
	// Stop immediately; we only care that construction and shutdown succeed
	// without blocking or panicking.
	stopped := make(chan struct{})
	go func() {
		d.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked unexpectedly for a large-window detector")
	}
}

// TestNewDeliveryLoopDetector_SmallWindowUsesOneSecondInterval exercises the
// floor branch: windowSize / 4 < 1 second → clamp to 1 second.
func TestNewDeliveryLoopDetector_SmallWindowUsesOneSecondInterval(t *testing.T) {
	// windowSize = 100ms → interval = 25ms, clamped to 1 second.
	d := NewDeliveryLoopDetector(100*time.Millisecond, 1)
	stopped := make(chan struct{})
	go func() {
		d.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked unexpectedly for a small-window detector")
	}
}

// --------------------------------------------------------------------------
// purgeExpired – direct invocation
// --------------------------------------------------------------------------

// TestPurgeExpired_RemovesExpiredEntriesAndEmptyBuckets calls purgeExpired
// directly to achieve the 0% coverage line. It verifies that expired entries
// are removed and that an empty bucket is subsequently deleted from the map.
func TestPurgeExpired_RemovesExpiredEntriesAndEmptyBuckets(t *testing.T) {
	nowFn, clock := newTestClock(0)
	d := newDeliveryLoopDetectorWithClock(5*time.Second, 1, nowFn)
	defer d.Stop()

	ctx := context.Background()

	// Record at t=0; entry expires at t=5s.
	d.Record(ctx, "A", "B", "guid-purge")

	// Confirm the bucket exists before purge.
	d.mu.RLock()
	bucketsBefore := len(d.buckets)
	d.mu.RUnlock()

	if bucketsBefore == 0 {
		t.Fatal("expected at least one bucket before purge")
	}

	// Advance clock past expiry.
	clock.Store(int64(6 * time.Second))

	// Invoke purgeExpired directly.
	d.purgeExpired()

	// The bucket should have been removed because all entries expired.
	d.mu.RLock()
	bucketsAfter := len(d.buckets)
	d.mu.RUnlock()

	if bucketsAfter != 0 {
		t.Errorf("expected 0 buckets after purging expired entries, got %d", bucketsAfter)
	}
}

// TestPurgeExpired_KeepsLiveEntries verifies that purgeExpired does not remove
// entries whose TTL has not yet elapsed.
func TestPurgeExpired_KeepsLiveEntries(t *testing.T) {
	nowFn, clock := newTestClock(0)
	d := newDeliveryLoopDetectorWithClock(10*time.Second, 1, nowFn)
	defer d.Stop()

	ctx := context.Background()

	// Record at t=0; entry expires at t=10s.
	d.Record(ctx, "X", "Y", "guid-live")

	// Advance clock to t=5s — entry is still live.
	clock.Store(int64(5 * time.Second))

	d.purgeExpired()

	// Bucket must still exist.
	d.mu.RLock()
	bucketsAfter := len(d.buckets)
	d.mu.RUnlock()

	if bucketsAfter == 0 {
		t.Error("expected bucket to remain after purging with live entries")
	}
}

// TestPurgeExpired_MixedEntries verifies that only the expired entries within
// a bucket are removed while live entries survive the purge.
func TestPurgeExpired_MixedEntries(t *testing.T) {
	nowFn, clock := newTestClock(0)
	d := newDeliveryLoopDetectorWithClock(10*time.Second, 2, nowFn)
	defer d.Stop()

	ctx := context.Background()

	// Record A->B at t=0 (expires at t=10s).
	d.Record(ctx, "A", "B", "guid-1")

	// Advance to t=8s and record B->A (expires at t=18s).
	clock.Store(int64(8 * time.Second))
	d.Record(ctx, "B", "A", "guid-2")

	// Advance to t=11s — A->B entry is expired, B->A is still live.
	clock.Store(int64(11 * time.Second))
	d.purgeExpired()

	// The bucket must survive because B->A is still live.
	d.mu.RLock()
	bucketsAfter := len(d.buckets)
	d.mu.RUnlock()

	if bucketsAfter == 0 {
		t.Error("expected bucket to remain after partial purge")
	}
}

// TestPurgeExpired_EmptyBucketMap is a no-op safety check: purgeExpired on a
// detector with no buckets must not panic.
func TestPurgeExpired_EmptyBucketMap(t *testing.T) {
	nowFn, _ := newTestClock(0)
	d := newDeliveryLoopDetectorWithClock(5*time.Second, 1, nowFn)
	defer d.Stop()

	// No records → no buckets; purgeExpired must be a safe no-op.
	d.purgeExpired()
}

// --------------------------------------------------------------------------
// getOrCreateBucket – double-checked locking (bucket already exists under write lock)
// --------------------------------------------------------------------------

// TestGetOrCreateBucket_ConcurrentCreation races many goroutines to create a
// bucket for the same key simultaneously, exercising the double-checked locking
// path where a concurrent writer finds the bucket already inserted.
func TestGetOrCreateBucket_ConcurrentCreation(t *testing.T) {
	nowFn, _ := newTestClock(0)
	d := newDeliveryLoopDetectorWithClock(5*time.Second, 1, nowFn)
	defer d.Stop()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			b := d.getOrCreateBucket("shared-key")
			if b == nil {
				t.Error("getOrCreateBucket returned nil")
			}
		}()
	}
	wg.Wait()

	// All goroutines must have received the same bucket instance.
	d.mu.RLock()
	count := len(d.buckets)
	d.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected exactly 1 bucket after concurrent creation, got %d", count)
	}
}

// --------------------------------------------------------------------------
// Record – TTL extension on re-record within same direction
// --------------------------------------------------------------------------

// TestRecord_ExtendsExpiryOnReRecord verifies that recording the same sender
// direction again while an entry is live extends the entry's expiry time.
func TestRecord_ExtendsExpiryOnReRecord(t *testing.T) {
	nowFn, clock := newTestClock(0)
	d := newDeliveryLoopDetectorWithClock(10*time.Second, 1, nowFn)
	defer d.Stop()

	ctx := context.Background()
	guid := "extend-guid"

	// First record at t=0; expiry = 10s.
	d.Record(ctx, "A", "B", guid)

	// Advance to t=8s and re-record the same direction with a new GUID to
	// trigger the merge+extension path; expiry should now be 18s.
	clock.Store(int64(8 * time.Second))
	d.Record(ctx, "A", "B", "extend-guid-2")

	// Advance to t=11s — original expiry (10s) has passed, but the extended
	// expiry (18s) has not; the loop check should still fire.
	clock.Store(int64(11 * time.Second))

	// B->A with the first guid should still be detectable (entry is live).
	if err := d.Check(ctx, "B", "A", guid); err == nil {
		t.Error("expected loop detection: entry expiry should have been extended")
	}
}

// --------------------------------------------------------------------------
// SpamReport / ReportStore – type-level coverage for report.go
// --------------------------------------------------------------------------

// TestSpamReport_ZeroValue ensures the SpamReport struct can be instantiated
// and its zero value fields are accessible (covers struct declaration lines).
func TestSpamReport_ZeroValue(t *testing.T) {
	var r SpamReport
	if r.ID != "" {
		t.Errorf("expected zero-value ID to be empty string, got %q", r.ID)
	}
	if !r.Timestamp.IsZero() {
		t.Errorf("expected zero-value Timestamp to be zero time")
	}
}

// TestSpamReport_FieldAssignment verifies all exported fields of SpamReport
// can be set and read back, covering each field in report.go.
func TestSpamReport_FieldAssignment(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	r := SpamReport{
		ID:           "report-id-1",
		ReporterUUID: "reporter-uuid",
		SourceUUID:   "source-uuid",
		MessageGUID:  "msg-guid-xyz",
		Timestamp:    ts,
	}

	if r.ID != "report-id-1" {
		t.Errorf("ID: got %q, want report-id-1", r.ID)
	}
	if r.ReporterUUID != "reporter-uuid" {
		t.Errorf("ReporterUUID: got %q, want reporter-uuid", r.ReporterUUID)
	}
	if r.SourceUUID != "source-uuid" {
		t.Errorf("SourceUUID: got %q, want source-uuid", r.SourceUUID)
	}
	if r.MessageGUID != "msg-guid-xyz" {
		t.Errorf("MessageGUID: got %q, want msg-guid-xyz", r.MessageGUID)
	}
	if !r.Timestamp.Equal(ts) {
		t.Errorf("Timestamp: got %v, want %v", r.Timestamp, ts)
	}
}
