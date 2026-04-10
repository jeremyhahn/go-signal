package messages

import (
	"context"
	"time"
)

// SpamReport represents a spam report submitted by an account against a
// specific message. Reports are persisted for downstream abuse-detection
// processing.
type SpamReport struct {
	// ID is the unique identifier assigned when the report is stored.
	ID string
	// ReporterUUID is the UUID of the account that submitted the report.
	ReporterUUID string
	// SourceUUID is the UUID of the account that sent the reported message.
	SourceUUID string
	// MessageGUID is the server-assigned GUID of the reported message.
	MessageGUID string
	// Timestamp is the wall-clock time at which the report was recorded.
	Timestamp time.Time
}

// ReportStore defines persistence operations for spam reports. All methods
// must be safe for concurrent use.
type ReportStore interface {
	// Store persists a new spam report. The report's ID field is set by the
	// implementation before returning.
	Store(ctx context.Context, report *SpamReport) error

	// GetByReporter returns all spam reports filed by the given account UUID.
	// An empty slice (not nil) is returned when no reports exist.
	GetByReporter(ctx context.Context, reporterUUID string) ([]*SpamReport, error)
}
