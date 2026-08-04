package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// newReport builds a SpamReport for tests with all fields populated.
func newReport(reporterUUID, sourceUUID string) *messages.SpamReport {
	return &messages.SpamReport{
		ReporterUUID: reporterUUID,
		SourceUUID:   sourceUUID,
		MessageGUID:  uuid.NewString(),
		Timestamp:    time.Now().UTC().Truncate(time.Microsecond),
	}
}

func TestReports_Store_GetByReporter_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewReportStore(c.Pool())
	ctx := context.Background()

	reporter := uuid.NewString()
	source := uuid.NewString()
	r := newReport(reporter, source)

	if err := s.Store(ctx, r); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if r.ID == "" {
		t.Fatal("Store must assign a non-empty ID")
	}

	got, err := s.GetByReporter(ctx, reporter)
	if err != nil {
		t.Fatalf("GetByReporter: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 report, got %d", len(got))
	}
	g := got[0]
	if g.ID != r.ID {
		t.Errorf("ID: got %q, want %q", g.ID, r.ID)
	}
	if g.ReporterUUID != reporter {
		t.Errorf("ReporterUUID: got %q, want %q", g.ReporterUUID, reporter)
	}
	if g.SourceUUID != source {
		t.Errorf("SourceUUID: got %q, want %q", g.SourceUUID, source)
	}
	if g.MessageGUID != r.MessageGUID {
		t.Errorf("MessageGUID: got %q, want %q", g.MessageGUID, r.MessageGUID)
	}
}

func TestReports_Store_IDGeneratedWhenEmpty(t *testing.T) {
	c := newTestClient(t)
	s := NewReportStore(c.Pool())
	ctx := context.Background()

	r := newReport(uuid.NewString(), uuid.NewString())
	r.ID = "" // ensure the store generates it

	if err := s.Store(ctx, r); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if r.ID == "" {
		t.Fatal("expected Store to generate a non-empty ID")
	}
}

func TestReports_GetByReporter_EmptySliceWhenNone(t *testing.T) {
	c := newTestClient(t)
	s := NewReportStore(c.Pool())
	ctx := context.Background()

	got, err := s.GetByReporter(ctx, uuid.NewString())
	if err != nil {
		t.Fatalf("GetByReporter: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 reports, got %d", len(got))
	}
}

func TestReports_GetByReporter_MultipleReports_OrderedByTimestampDesc(t *testing.T) {
	c := newTestClient(t)
	s := NewReportStore(c.Pool())
	ctx := context.Background()

	reporter := uuid.NewString()
	guids := make([]string, 3)
	for i := range guids {
		r := newReport(reporter, uuid.NewString())
		r.Timestamp = time.Now().UTC().Add(time.Duration(i) * time.Millisecond).Truncate(time.Microsecond)
		if err := s.Store(ctx, r); err != nil {
			t.Fatalf("Store[%d]: %v", i, err)
		}
		guids[i] = r.ID
	}

	got, err := s.GetByReporter(ctx, reporter)
	if err != nil {
		t.Fatalf("GetByReporter: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 reports, got %d", len(got))
	}
	// Verify DESC order: most-recent (index 2) appears first.
	if got[0].ID != guids[2] {
		t.Errorf("expected most recent report first, got ID %q, want %q", got[0].ID, guids[2])
	}
}

func TestReports_GetByReporter_DoesNotBleedAcrossReporters(t *testing.T) {
	c := newTestClient(t)
	s := NewReportStore(c.Pool())
	ctx := context.Background()

	reporter1 := uuid.NewString()
	reporter2 := uuid.NewString()

	r1 := newReport(reporter1, uuid.NewString())
	r2 := newReport(reporter2, uuid.NewString())

	if err := s.Store(ctx, r1); err != nil {
		t.Fatalf("Store r1: %v", err)
	}
	if err := s.Store(ctx, r2); err != nil {
		t.Fatalf("Store r2: %v", err)
	}

	got1, err := s.GetByReporter(ctx, reporter1)
	if err != nil {
		t.Fatalf("GetByReporter reporter1: %v", err)
	}
	if len(got1) != 1 || got1[0].ID != r1.ID {
		t.Fatalf("reporter1: expected only r1, got %v", got1)
	}

	got2, err := s.GetByReporter(ctx, reporter2)
	if err != nil {
		t.Fatalf("GetByReporter reporter2: %v", err)
	}
	if len(got2) != 1 || got2[0].ID != r2.ID {
		t.Fatalf("reporter2: expected only r2, got %v", got2)
	}
}

func TestReports_Store_NilReport_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewReportStore(c.Pool())

	err := s.Store(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil report, got nil")
	}
}

func TestReports_Store_EmptyReporterUUID_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewReportStore(c.Pool())

	r := newReport("", uuid.NewString())
	err := s.Store(context.Background(), r)
	if err == nil {
		t.Fatal("expected error for empty reporter UUID, got nil")
	}
}

func TestReports_Store_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewReportStore(c.Pool())
	c.Close()

	r := newReport(uuid.NewString(), uuid.NewString())
	err := s.Store(context.Background(), r)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestReports_GetByReporter_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewReportStore(c.Pool())
	c.Close()

	_, err := s.GetByReporter(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

// TestReports_Store_ZeroTimestamp_AutoFilled verifies that Store sets
// Timestamp to NOW() when the caller leaves it at the zero value
// (reports.go line 45-47: `if report.Timestamp.IsZero() { ... }`).
func TestReports_Store_ZeroTimestamp_AutoFilled(t *testing.T) {
	c := newTestClient(t)
	s := NewReportStore(c.Pool())
	ctx := context.Background()

	reporter := uuid.NewString()
	r := &messages.SpamReport{
		ReporterUUID: reporter,
		SourceUUID:   uuid.NewString(),
		// Timestamp intentionally left zero so the store fills it in.
	}
	if err := s.Store(ctx, r); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if r.Timestamp.IsZero() {
		t.Fatal("expected Store to populate Timestamp when zero, but it is still zero")
	}

	got, err := s.GetByReporter(ctx, reporter)
	if err != nil {
		t.Fatalf("GetByReporter: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 report, got %d", len(got))
	}
	if got[0].Timestamp.IsZero() {
		t.Fatal("stored Timestamp is zero after roundtrip")
	}
}

func TestReports_Store_NullableFields_RoundtripClean(t *testing.T) {
	c := newTestClient(t)
	s := NewReportStore(c.Pool())
	ctx := context.Background()

	// Store a report with empty optional fields.
	r := &messages.SpamReport{
		ReporterUUID: uuid.NewString(),
		SourceUUID:   "",
		MessageGUID:  "",
		Timestamp:    time.Now().UTC().Truncate(time.Microsecond),
	}
	if err := s.Store(ctx, r); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := s.GetByReporter(ctx, r.ReporterUUID)
	if err != nil {
		t.Fatalf("GetByReporter: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 report, got %d", len(got))
	}
	// Empty strings must come back as empty strings, not some NULL artifact.
	if got[0].SourceUUID != "" || got[0].MessageGUID != "" {
		t.Errorf("nullable fields: got SourceUUID=%q MessageGUID=%q, want empty",
			got[0].SourceUUID, got[0].MessageGUID)
	}
}
