package qrdb

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

func newReport(reporterUUID, sourceUUID, messageGUID string) *messages.SpamReport {
	return &messages.SpamReport{
		ReporterUUID: reporterUUID,
		SourceUUID:   sourceUUID,
		MessageGUID:  messageGUID,
		Timestamp:    time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC),
	}
}

func TestReportStore_Store_AssignsID(t *testing.T) {
	t.Parallel()
	s := NewReportStore(NewFakeKVStore())
	// Deterministic ID generator for test reproducibility.
	counter := 0
	s.newID = func() string { counter++; return "id-" + strconv.Itoa(counter) }

	r := newReport("reporter-1", "source-1", "msg-1")
	if err := s.Store(context.Background(), r); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if r.ID != "id-1" {
		t.Fatalf("expected ID to be assigned: %+v", r)
	}
}

func TestReportStore_Store_PreservesCallerID(t *testing.T) {
	t.Parallel()
	s := NewReportStore(NewFakeKVStore())
	s.newID = func() string { return "should-not-be-used" }

	r := newReport("reporter-1", "source-1", "msg-1")
	r.ID = "caller-id"
	if err := s.Store(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if r.ID != "caller-id" {
		t.Fatalf("Store must not overwrite a caller-provided ID: %s", r.ID)
	}
}

func TestReportStore_Store_Invalid(t *testing.T) {
	t.Parallel()
	s := NewReportStore(NewFakeKVStore())
	if err := s.Store(context.Background(), nil); err == nil {
		t.Fatal("expected error for nil report")
	}
	if err := s.Store(context.Background(), &messages.SpamReport{}); err == nil {
		t.Fatal("expected error for empty reporter UUID")
	}
}

func TestReportStore_GetByReporter_ReturnsAllReports(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewReportStore(NewFakeKVStore())
	counter := 0
	s.newID = func() string { counter++; return "id-" + strconv.Itoa(counter) }

	for i := 0; i < 3; i++ {
		r := newReport("r1", "source", "msg-"+strconv.Itoa(i))
		if err := s.Store(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	// One report for a different reporter.
	if err := s.Store(ctx, newReport("r2", "source", "msg-other")); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetByReporter(ctx, "r1")
	if err != nil {
		t.Fatalf("GetByReporter: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 reports for r1, got %d", len(got))
	}
}

func TestReportStore_GetByReporter_EmptyReturnsEmptySlice(t *testing.T) {
	t.Parallel()
	s := NewReportStore(NewFakeKVStore())
	got, err := s.GetByReporter(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("GetByReporter: %v", err)
	}
	if got == nil {
		t.Fatal("GetByReporter must return non-nil empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %d entries", len(got))
	}
}

func TestReportStore_DefaultIDGenerator_ReturnsValidUUID(t *testing.T) {
	t.Parallel()
	s := NewReportStore(NewFakeKVStore())
	r := newReport("r1", "s1", "m1")
	if err := s.Store(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if len(r.ID) != 36 { // UUID string length
		t.Fatalf("expected UUID-shaped ID, got %q (len %d)", r.ID, len(r.ID))
	}
}
