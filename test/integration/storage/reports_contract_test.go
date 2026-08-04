package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/messages"
	memorystorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// newTestSpamReport returns a minimal SpamReport for testing.
func newTestSpamReport(reporterUUID string) *messages.SpamReport {
	return &messages.SpamReport{
		ReporterUUID: reporterUUID,
		SourceUUID:   uuid.NewString(),
		MessageGUID:  uuid.NewString(),
		Timestamp:    time.Now().UTC().Truncate(time.Second),
	}
}

// runReportStoreContract drives every behavioral expectation of
// messages.ReportStore across all backends.
func runReportStoreContract(t *testing.T, factory func(t *testing.T) messages.ReportStore) {
	t.Helper()

	t.Run("Store_AssignsID", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		report := newTestSpamReport(uuid.NewString())

		require.NoError(t, s.Store(ctx, report))
		assert.NotEmpty(t, report.ID)
	})

	t.Run("Store_GetByReporter_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		reporterUUID := uuid.NewString()
		report := newTestSpamReport(reporterUUID)

		require.NoError(t, s.Store(ctx, report))

		reports, err := s.GetByReporter(ctx, reporterUUID)
		require.NoError(t, err)
		require.Len(t, reports, 1)
		assert.Equal(t, report.ID, reports[0].ID)
		assert.Equal(t, reporterUUID, reports[0].ReporterUUID)
		assert.Equal(t, report.SourceUUID, reports[0].SourceUUID)
		assert.Equal(t, report.MessageGUID, reports[0].MessageGUID)
	})

	t.Run("GetByReporter_Empty_ReturnsSlice", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		reports, err := s.GetByReporter(ctx, uuid.NewString())
		require.NoError(t, err)
		assert.NotNil(t, reports)
		assert.Len(t, reports, 0)
	})

	t.Run("Store_MultipleReports_SameReporter", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		reporterUUID := uuid.NewString()

		r1 := newTestSpamReport(reporterUUID)
		r2 := newTestSpamReport(reporterUUID)
		r3 := newTestSpamReport(reporterUUID)

		require.NoError(t, s.Store(ctx, r1))
		require.NoError(t, s.Store(ctx, r2))
		require.NoError(t, s.Store(ctx, r3))

		reports, err := s.GetByReporter(ctx, reporterUUID)
		require.NoError(t, err)
		assert.Len(t, reports, 3)

		// All IDs must be unique and non-empty.
		seen := map[string]struct{}{}
		for _, r := range reports {
			assert.NotEmpty(t, r.ID)
			_, dup := seen[r.ID]
			assert.False(t, dup, "duplicate report ID: %s", r.ID)
			seen[r.ID] = struct{}{}
		}
	})

	t.Run("ReporterIsolation", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		reporter1 := uuid.NewString()
		reporter2 := uuid.NewString()

		require.NoError(t, s.Store(ctx, newTestSpamReport(reporter1)))
		require.NoError(t, s.Store(ctx, newTestSpamReport(reporter1)))

		require.NoError(t, s.Store(ctx, newTestSpamReport(reporter2)))

		r1, err := s.GetByReporter(ctx, reporter1)
		require.NoError(t, err)
		assert.Len(t, r1, 2)

		r2, err := s.GetByReporter(ctx, reporter2)
		require.NoError(t, err)
		assert.Len(t, r2, 1)
	})

	t.Run("Store_TimestampPreserved", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		reporterUUID := uuid.NewString()
		report := newTestSpamReport(reporterUUID)
		// Explicit timestamp — backends must not overwrite it.
		report.Timestamp = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

		require.NoError(t, s.Store(ctx, report))

		reports, err := s.GetByReporter(ctx, reporterUUID)
		require.NoError(t, err)
		require.Len(t, reports, 1)
		// Allow ±1s to account for backends that round to second precision.
		diff := reports[0].Timestamp.Sub(report.Timestamp)
		if diff < 0 {
			diff = -diff
		}
		assert.LessOrEqual(t, diff, time.Second, "timestamp should be preserved within 1s")
	})
}

// TestReportStoreContract_Memory runs the report contract against the
// in-memory backend.
func TestReportStoreContract_Memory(t *testing.T) {
	runReportStoreContract(t, func(t *testing.T) messages.ReportStore {
		return memorystorage.NewMemoryReportStore()
	})
}

// TestReportStoreContract_QRDB runs the report contract against the qrdb
// (FakeKVStore) backend.
func TestReportStoreContract_QRDB(t *testing.T) {
	runReportStoreContract(t, func(t *testing.T) messages.ReportStore {
		return qrdbstorage.NewReportStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestReportStoreContract_Postgres runs the report contract against a live
// Postgres instance. Skips if TEST_POSTGRES_URL is unset.
func TestReportStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runReportStoreContract(t, func(t *testing.T) messages.ReportStore {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return postgres.NewReportStore(c.Pool())
	})
}
