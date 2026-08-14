package messages

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// newTestClock returns a monotonically increasing clock function and an
// atomic int64 that callers can set to advance time.
func newTestClock(initialNano int64) (nowFn func() int64, clock *atomic.Int64) {
	c := &atomic.Int64{}
	c.Store(initialNano)
	return func() int64 { return c.Load() }, c
}

// --------------------------------------------------------------------------
// pairKey
// --------------------------------------------------------------------------

func TestPairKey_IsDirectionAgnostic(t *testing.T) {
	k1 := pairKey("aaa", "bbb")
	k2 := pairKey("bbb", "aaa")
	if k1 != k2 {
		t.Errorf("pairKey must be direction-agnostic: %q != %q", k1, k2)
	}
}

func TestPairKey_DifferentPairsAreDistinct(t *testing.T) {
	k1 := pairKey("alice", "bob")
	k2 := pairKey("alice", "carol")
	if k1 == k2 {
		t.Error("different pairs must produce different keys")
	}
}

func TestPairKey_SamePairBothDirectionsSameKey(t *testing.T) {
	a := "uuid-000-a"
	b := "uuid-000-b"
	if pairKey(a, b) != pairKey(b, a) {
		t.Error("pairKey(a,b) must equal pairKey(b,a)")
	}
}

// --------------------------------------------------------------------------
// DeliveryLoopError
// --------------------------------------------------------------------------

func TestDeliveryLoopError_MessageContainsFields(t *testing.T) {
	err := &DeliveryLoopError{
		SenderUUID:    "sender-uuid",
		RecipientUUID: "recipient-uuid",
		MessageGUID:   "guid-123",
	}
	msg := err.Error()
	if msg == "" {
		t.Error("DeliveryLoopError.Error() must return a non-empty string")
	}
}

func TestDeliveryLoopError_IsTypedError(t *testing.T) {
	var target *DeliveryLoopError
	err := &DeliveryLoopError{SenderUUID: "a", RecipientUUID: "b", MessageGUID: "g"}
	if !errors.As(err, &target) {
		t.Error("errors.As must unwrap DeliveryLoopError")
	}
}

// --------------------------------------------------------------------------
// DeliveryLoopDetector – normal flow (no loop)
// --------------------------------------------------------------------------

func TestDeliveryLoopDetector_NormalFlow_NoError(t *testing.T) {
	d := NewDeliveryLoopDetector(5*time.Second, 2)
	defer d.Stop()

	ctx := context.Background()

	// A sends to B — no history yet.
	if err := d.Check(ctx, "A", "B", "guid-1"); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	d.Record(ctx, "A", "B", "guid-1")

	// A sends another message to B with a different GUID — still fine.
	if err := d.Check(ctx, "A", "B", "guid-2"); err != nil {
		t.Errorf("expected no error for second message A->B, got: %v", err)
	}
	d.Record(ctx, "A", "B", "guid-2")
}

func TestDeliveryLoopDetector_DifferentGUIDs_NoFalsePositive(t *testing.T) {
	d := NewDeliveryLoopDetector(5*time.Second, 2)
	defer d.Stop()

	ctx := context.Background()

	// A->B with guid-1
	d.Record(ctx, "A", "B", "guid-1")

	// B->A with a DIFFERENT guid should NOT be a loop.
	if err := d.Check(ctx, "B", "A", "guid-2"); err != nil {
		t.Errorf("different GUIDs must not trigger loop detection, got: %v", err)
	}
}

func TestDeliveryLoopDetector_UnrelatedPairs_NoInterference(t *testing.T) {
	d := NewDeliveryLoopDetector(5*time.Second, 2)
	defer d.Stop()

	ctx := context.Background()

	// A->B loop recorded.
	d.Record(ctx, "A", "B", "guid-1")

	// C->D should be completely independent.
	if err := d.Check(ctx, "C", "D", "guid-1"); err != nil {
		t.Errorf("unrelated pair must not trigger loop detection, got: %v", err)
	}
}

// --------------------------------------------------------------------------
// DeliveryLoopDetector – loop detection
// --------------------------------------------------------------------------

func TestDeliveryLoopDetector_ABALoop_Detected(t *testing.T) {
	d := NewDeliveryLoopDetector(10*time.Second, 1)
	defer d.Stop()

	ctx := context.Background()
	guid := "loop-guid-1"

	// A sends to B.
	d.Record(ctx, "A", "B", guid)

	// B sends the same GUID back to A — loop detected.
	err := d.Check(ctx, "B", "A", guid)
	if err == nil {
		t.Fatal("expected loop detection error, got nil")
	}
	var loopErr *DeliveryLoopError
	if !errors.As(err, &loopErr) {
		t.Fatalf("expected *DeliveryLoopError, got %T: %v", err, err)
	}
}

func TestDeliveryLoopDetector_BALoop_Detected_ReverseOrder(t *testing.T) {
	d := NewDeliveryLoopDetector(10*time.Second, 1)
	defer d.Stop()

	ctx := context.Background()
	guid := "loop-guid-reverse"

	// B sends to A first.
	d.Record(ctx, "B", "A", guid)

	// A tries to send the same GUID to B — loop detected.
	err := d.Check(ctx, "A", "B", guid)
	if err == nil {
		t.Fatal("expected loop detection error for reverse direction, got nil")
	}
}

func TestDeliveryLoopDetector_LoopError_ContainsUUIDs(t *testing.T) {
	d := NewDeliveryLoopDetector(10*time.Second, 1)
	defer d.Stop()

	ctx := context.Background()
	guid := "loop-info-guid"

	d.Record(ctx, "sender-1", "recipient-1", guid)

	err := d.Check(ctx, "recipient-1", "sender-1", guid)
	if err == nil {
		t.Fatal("expected loop error, got nil")
	}
	var loopErr *DeliveryLoopError
	if !errors.As(err, &loopErr) {
		t.Fatalf("expected *DeliveryLoopError, got %T", err)
	}
	if loopErr.SenderUUID != "recipient-1" {
		t.Errorf("SenderUUID: got %q, want recipient-1", loopErr.SenderUUID)
	}
	if loopErr.RecipientUUID != "sender-1" {
		t.Errorf("RecipientUUID: got %q, want sender-1", loopErr.RecipientUUID)
	}
	if loopErr.MessageGUID != guid {
		t.Errorf("MessageGUID: got %q, want %q", loopErr.MessageGUID, guid)
	}
}

// --------------------------------------------------------------------------
// DeliveryLoopDetector – TTL expiry
// --------------------------------------------------------------------------

func TestDeliveryLoopDetector_ExpiredEntries_DoNotTrigger(t *testing.T) {
	nowFn, clock := newTestClock(0)
	d := newDeliveryLoopDetectorWithClock(5*time.Second, 1, nowFn)
	defer d.Stop()

	ctx := context.Background()
	guid := "expiry-guid"

	// Record A->B at t=0.
	d.Record(ctx, "A", "B", guid)

	// Advance clock past the window (5s + 1ns).
	clock.Store(int64(5*time.Second) + 1)

	// B->A should NOT be detected because the A->B entry has expired.
	if err := d.Check(ctx, "B", "A", guid); err != nil {
		t.Errorf("expired entry must not trigger loop detection, got: %v", err)
	}
}

func TestDeliveryLoopDetector_ActiveEntryWithinWindow_Detects(t *testing.T) {
	nowFn, clock := newTestClock(0)
	d := newDeliveryLoopDetectorWithClock(10*time.Second, 1, nowFn)
	defer d.Stop()

	ctx := context.Background()
	guid := "window-guid"

	// Record A->B at t=0.
	d.Record(ctx, "A", "B", guid)

	// Advance to just before expiry (9s).
	clock.Store(int64(9 * time.Second))

	// B->A within the window must be detected.
	if err := d.Check(ctx, "B", "A", guid); err == nil {
		t.Error("expected loop detection within window, got nil")
	}
}

// --------------------------------------------------------------------------
// DeliveryLoopDetector – concurrent access safety
// --------------------------------------------------------------------------

func TestDeliveryLoopDetector_ConcurrentRecordAndCheck_NoDataRace(t *testing.T) {
	d := NewDeliveryLoopDetector(10*time.Second, 5)
	defer d.Stop()

	ctx := context.Background()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Writers: concurrent Record calls.
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			for j := range 10 {
				_ = j
				d.Record(ctx, "sender", "recipient", "guid-concurrent")
			}
			_ = i
		}(i)
	}

	// Readers: concurrent Check calls.
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			for range 10 {
				_ = d.Check(ctx, "recipient", "sender", "guid-concurrent")
			}
			_ = i
		}(i)
	}

	wg.Wait()
}

func TestDeliveryLoopDetector_ConcurrentDifferentPairs_NoInterference(t *testing.T) {
	d := NewDeliveryLoopDetector(10*time.Second, 1)
	defer d.Stop()

	ctx := context.Background()
	pairs := [][2]string{
		{"A", "B"}, {"C", "D"}, {"E", "F"}, {"G", "H"}, {"I", "J"},
	}

	var wg sync.WaitGroup
	for _, p := range pairs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Record(ctx, p[0], p[1], "guid-shared")
		}()
	}
	wg.Wait()

	// None of the pairs should report a loop for their own GUID.
	for _, p := range pairs {
		// Same direction — no loop.
		if err := d.Check(ctx, p[0], p[1], "guid-shared"); err != nil {
			t.Errorf("pair %v same direction should not be a loop, got: %v", p, err)
		}
		// Reverse direction with the shared GUID — could detect a loop since
		// all pairs recorded the same GUID, but each pair is bucketed
		// independently so only within-pair entries count.
		// This test just ensures there is no panic or data corruption.
		_ = d.Check(ctx, p[1], p[0], "guid-shared")
	}
}

// --------------------------------------------------------------------------
// DeliveryLoopDetector – Stop
// --------------------------------------------------------------------------

func TestDeliveryLoopDetector_StopIsIdempotent(t *testing.T) {
	d := NewDeliveryLoopDetector(5*time.Second, 1)
	d.Stop()
	// Second Stop must not panic or block.
	d.Stop()
}

func TestDeliveryLoopDetector_MaxChainLengthFloor(t *testing.T) {
	// maxChainLength < 1 is clamped to 1.
	d := NewDeliveryLoopDetector(5*time.Second, 0)
	defer d.Stop()
	if d.maxChainLength != 1 {
		t.Errorf("expected maxChainLength=1 after clamping 0, got %d", d.maxChainLength)
	}
}

// --------------------------------------------------------------------------
// DeliveryLoopDetector – GUID cap (CONC-4)
// --------------------------------------------------------------------------

// TestRecord_GUIDCapPreventsUnboundedGrowth verifies that once maxGUIDsPerEntry
// is reached for a given direction the guids map stops growing.
func TestRecord_GUIDCapPreventsUnboundedGrowth(t *testing.T) {
	ctx := context.Background()
	window := time.Hour
	nowFn, _ := newTestClock(time.Now().UnixNano())
	d := newDeliveryLoopDetectorWithClock(window, 2, nowFn)
	defer d.Stop()

	const sender = "alice"
	const recipient = "bob"

	// Record maxGUIDsPerEntry + 100 distinct GUIDs in the same direction.
	const extra = 100
	for i := 0; i < maxGUIDsPerEntry+extra; i++ {
		guid := "guid-" + string(rune('A'+i%26)) + "-" + string(rune('0'+i%10))
		d.Record(ctx, sender, recipient, guid)
	}

	// Retrieve the bucket and confirm the guids map is capped.
	key := pairKey(sender, recipient)
	d.mu.RLock()
	b := d.buckets[key]
	d.mu.RUnlock()

	if b == nil {
		t.Fatal("expected bucket to exist")
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	var guidCount int
	for _, entry := range b.entries {
		if entry.sender == sender {
			guidCount = len(entry.guids)
			break
		}
	}

	if guidCount > maxGUIDsPerEntry {
		t.Errorf("expected guids map capped at %d, got %d", maxGUIDsPerEntry, guidCount)
	}
}

// TestRecord_GUIDCapDoesNotPreventLoopDetection verifies that a loop is still
// detectable after the cap has been reached — because the offending GUID was
// recorded before the cap was hit.
func TestRecord_GUIDCapDoesNotPreventLoopDetection(t *testing.T) {
	ctx := context.Background()
	window := time.Hour
	nowFn, _ := newTestClock(time.Now().UnixNano())
	d := newDeliveryLoopDetectorWithClock(window, 2, nowFn)
	defer d.Stop()

	const sender = "alice"
	const recipient = "bob"
	const loopGUID = "loop-guid-early"

	// Record the loop-trigger GUID first (before the cap).
	d.Record(ctx, sender, recipient, loopGUID)

	// Flood additional GUIDs to reach the cap.
	for i := 0; i < maxGUIDsPerEntry; i++ {
		d.Record(ctx, sender, recipient, "flood-"+string(rune('A'+i%26))+"-"+string(rune('0'+i%10)))
	}

	// The reverse-direction check for loopGUID must still detect the loop.
	err := d.Check(ctx, recipient, sender, loopGUID)
	if err == nil {
		t.Fatal("expected loop to be detected for early-recorded GUID even after cap")
	}
	var loopErr *DeliveryLoopError
	if !errors.As(err, &loopErr) {
		t.Fatalf("expected *DeliveryLoopError, got %T: %v", err, err)
	}
}
