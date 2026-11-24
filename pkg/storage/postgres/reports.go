package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// Compile-time interface satisfaction check.
var _ messages.ReportStore = (*ReportStore)(nil)

// ReportStore is a Postgres-backed implementation of messages.ReportStore.
//
// Schema: spam_reports(id UUID PK, reporter_uuid UUID, source_uuid UUID,
// message_guid UUID, reported_at TIMESTAMPTZ). source_uuid and message_guid
// are nullable in the schema (no FK constraint, reporters may omit them).
type ReportStore struct {
	q Querier
}

// NewReportStore constructs a ReportStore backed by the given Querier.
// Pass *pgxpool.Pool for normal use; pass pgx.Tx to participate in an outer
// transaction.
func NewReportStore(q Querier) *ReportStore {
	return &ReportStore{q: q}
}

// Store persists a new spam report. If report.ID is empty a UUID is generated
// and written back to the struct so callers can reference the stored ID.
// report.Timestamp is set to NOW() if zero.
func (s *ReportStore) Store(ctx context.Context, report *messages.SpamReport) error {
	if report == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres reports: nil report")
	}
	if report.ReporterUUID == "" {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "postgres reports: empty reporter UUID")
	}
	if report.ID == "" {
		report.ID = uuid.NewString()
	}
	if report.Timestamp.IsZero() {
		report.Timestamp = time.Now().UTC()
	}

	_, err := s.q.Exec(ctx, `
		INSERT INTO spam_reports (id, reporter_uuid, source_uuid, message_guid, reported_at)
		VALUES ($1, $2, $3, $4, $5)`,
		report.ID,
		report.ReporterUUID,
		nullableString(report.SourceUUID),
		nullableString(report.MessageGUID),
		report.Timestamp,
	)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres reports: insert", err)
	}
	return nil
}

// GetByReporter returns all spam reports filed by the given account UUID,
// ordered by reported_at DESC. Returns an empty slice (not nil) when none exist.
func (s *ReportStore) GetByReporter(ctx context.Context, reporterUUID string) ([]*messages.SpamReport, error) {
	rows, err := s.q.Query(ctx, `
		SELECT id, reporter_uuid, source_uuid, message_guid, reported_at
		FROM spam_reports
		WHERE reporter_uuid = $1
		ORDER BY reported_at DESC`,
		reporterUUID,
	)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres reports: query", err)
	}
	defer rows.Close()

	out := make([]*messages.SpamReport, 0)
	for rows.Next() {
		r, err := scanReport(rows)
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres reports: scan", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres reports: rows", err)
	}
	return out, nil
}

// scanReport reads one spam_reports row from the current cursor position.
// source_uuid and message_guid are scanned into *string because they are
// nullable in the schema; nil is converted to the empty string.
func scanReport(rows interface {
	Scan(dest ...any) error
}) (*messages.SpamReport, error) {
	var (
		id           string
		reporterUUID string
		sourceUUID   *string
		messageGUID  *string
		reportedAt   time.Time
	)
	if err := rows.Scan(&id, &reporterUUID, &sourceUUID, &messageGUID, &reportedAt); err != nil {
		return nil, err
	}
	r := &messages.SpamReport{
		ID:           id,
		ReporterUUID: reporterUUID,
		Timestamp:    reportedAt,
	}
	if sourceUUID != nil {
		r.SourceUUID = *sourceUUID
	}
	if messageGUID != nil {
		r.MessageGUID = *messageGUID
	}
	return r, nil
}
