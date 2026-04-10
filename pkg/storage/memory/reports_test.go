package memory

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// --------------------------------------------------------------------------
// MemoryReportStore
// --------------------------------------------------------------------------

func TestMemoryReportStore_StoreAndGetByReporter(t *testing.T) {
	store := NewMemoryReportStore()
	ctx := context.Background()

	report := &messages.SpamReport{
		ReporterUUID: "reporter-uuid-1",
		SourceUUID:   "source-uuid-1",
		MessageGUID:  "msg-guid-1",
	}

	if err := store.Store(ctx, report); err != nil {
		t.Fatalf("Store returned error: %v", err)
	}

	if report.ID == "" {
		t.Error("Store must assign a non-empty ID to the report")
	}
	if report.Timestamp.IsZero() {
		t.Error("Store must assign a non-zero Timestamp to the report")
	}

	results, err := store.GetByReporter(ctx, "reporter-uuid-1")
	if err != nil {
		t.Fatalf("GetByReporter returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].MessageGUID != "msg-guid-1" {
		t.Errorf("expected MessageGUID msg-guid-1, got %q", results[0].MessageGUID)
	}
	if results[0].SourceUUID != "source-uuid-1" {
		t.Errorf("expected SourceUUID source-uuid-1, got %q", results[0].SourceUUID)
	}
}

func TestMemoryReportStore_MultipleReportsSameReporter(t *testing.T) {
	store := NewMemoryReportStore()
	ctx := context.Background()

	for i := range 5 {
		r := &messages.SpamReport{
			ReporterUUID: "reporter-uuid-2",
			SourceUUID:   "source-uuid-2",
			MessageGUID:  "guid-" + string(rune('A'+i)),
		}
		if err := store.Store(ctx, r); err != nil {
			t.Fatalf("Store %d: unexpected error: %v", i, err)
		}
	}

	results, err := store.GetByReporter(ctx, "reporter-uuid-2")
	if err != nil {
		t.Fatalf("GetByReporter: %v", err)
	}
	if len(results) != 5 {
		t.Errorf("expected 5 reports, got %d", len(results))
	}
}

func TestMemoryReportStore_GetByReporter_EmptySliceWhenNone(t *testing.T) {
	store := NewMemoryReportStore()
	ctx := context.Background()

	results, err := store.GetByReporter(ctx, "nonexistent-reporter")
	if err != nil {
		t.Fatalf("GetByReporter: unexpected error: %v", err)
	}
	if results == nil {
		t.Error("GetByReporter must return a non-nil slice when no reports exist")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 reports, got %d", len(results))
	}
}

func TestMemoryReportStore_ReportersAreIsolated(t *testing.T) {
	store := NewMemoryReportStore()
	ctx := context.Background()

	_ = store.Store(ctx, &messages.SpamReport{
		ReporterUUID: "reporter-A",
		SourceUUID:   "source-1",
		MessageGUID:  "guid-1",
	})
	_ = store.Store(ctx, &messages.SpamReport{
		ReporterUUID: "reporter-B",
		SourceUUID:   "source-2",
		MessageGUID:  "guid-2",
	})

	rA, _ := store.GetByReporter(ctx, "reporter-A")
	if len(rA) != 1 {
		t.Errorf("reporter-A: expected 1 report, got %d", len(rA))
	}

	rB, _ := store.GetByReporter(ctx, "reporter-B")
	if len(rB) != 1 {
		t.Errorf("reporter-B: expected 1 report, got %d", len(rB))
	}
}

func TestMemoryReportStore_AssignsUniqueIDs(t *testing.T) {
	store := NewMemoryReportStore()
	ctx := context.Background()

	r1 := &messages.SpamReport{ReporterUUID: "r1", SourceUUID: "s", MessageGUID: "g1"}
	r2 := &messages.SpamReport{ReporterUUID: "r2", SourceUUID: "s", MessageGUID: "g2"}

	_ = store.Store(ctx, r1)
	_ = store.Store(ctx, r2)

	if r1.ID == r2.ID {
		t.Errorf("expected distinct IDs, both got %q", r1.ID)
	}
}

func TestMemoryReportStore_PreservesExistingTimestamp(t *testing.T) {
	store := NewMemoryReportStore()
	ctx := context.Background()

	fixed := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	r := &messages.SpamReport{
		ReporterUUID: "r",
		SourceUUID:   "s",
		MessageGUID:  "g",
		Timestamp:    fixed,
	}
	if err := store.Store(ctx, r); err != nil {
		t.Fatalf("Store: %v", err)
	}

	results, _ := store.GetByReporter(ctx, "r")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Timestamp.Equal(fixed) {
		t.Errorf("expected timestamp %v, got %v", fixed, results[0].Timestamp)
	}
}

func TestMemoryReportStore_ConcurrentStoreAndGet(t *testing.T) {
	store := NewMemoryReportStore()
	ctx := context.Background()

	const goroutines = 20
	const reportsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := range goroutines {
		go func(g int) {
			defer wg.Done()
			for i := range reportsPerGoroutine {
				r := &messages.SpamReport{
					ReporterUUID: "concurrent-reporter",
					SourceUUID:   "source",
					MessageGUID:  "guid-concurrent",
				}
				if err := store.Store(ctx, r); err != nil {
					// Use t.Errorf (not Fatal) since we are in a goroutine.
					t.Errorf("goroutine %d report %d: Store error: %v", g, i, err)
				}
			}
		}(g)
	}

	wg.Wait()

	results, err := store.GetByReporter(ctx, "concurrent-reporter")
	if err != nil {
		t.Fatalf("GetByReporter: %v", err)
	}
	want := goroutines * reportsPerGoroutine
	if len(results) != want {
		t.Errorf("expected %d reports after concurrent stores, got %d", want, len(results))
	}
}

func TestMemoryReportStore_GetReturnsClones(t *testing.T) {
	store := NewMemoryReportStore()
	ctx := context.Background()

	original := &messages.SpamReport{
		ReporterUUID: "clone-reporter",
		SourceUUID:   "clone-source",
		MessageGUID:  "clone-guid",
	}
	_ = store.Store(ctx, original)

	results, _ := store.GetByReporter(ctx, "clone-reporter")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	// Mutate the returned struct; the stored copy must not be affected.
	results[0].SourceUUID = "mutated"

	results2, _ := store.GetByReporter(ctx, "clone-reporter")
	if results2[0].SourceUUID == "mutated" {
		t.Error("GetByReporter must return independent clones, not references to internal storage")
	}
}
