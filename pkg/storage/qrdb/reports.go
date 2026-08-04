package qrdb

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// Key layout: report:{reporterUUID}:{reportID} → JSON SpamReport.
// Listing "report:{reporterUUID}:" returns the full set of reports filed by
// that account.
const reportKeyPrefix = "report:"

var _ messages.ReportStore = (*ReportStore)(nil)

// ReportStore is a qrdb-backed implementation of messages.ReportStore.
type ReportStore struct {
	kv    KVStore
	newID func() string // swappable in tests for deterministic IDs
}

// NewReportStore returns a ReportStore that persists to kv. IDs are
// generated with google/uuid.
func NewReportStore(kv KVStore) *ReportStore {
	return &ReportStore{kv: kv, newID: func() string { return uuid.NewString() }}
}

func reportKey(reporterUUID, reportID string) string {
	return reportKeyPrefix + reporterUUID + ":" + reportID
}
func reporterPrefix(reporterUUID string) string {
	return reportKeyPrefix + reporterUUID + ":"
}

// Store assigns an ID (if empty) and persists the report. The generated ID
// is written back to the passed-in struct so callers can use it.
func (s *ReportStore) Store(ctx context.Context, report *messages.SpamReport) error {
	if report == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb reports: nil report")
	}
	if report.ReporterUUID == "" {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb reports: empty reporter UUID")
	}
	if report.ID == "" {
		report.ID = s.newID()
	}

	data, err := json.Marshal(report)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb reports: marshal", err)
	}
	if err := s.kv.Put(ctx, reportKey(report.ReporterUUID, report.ID), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb reports: put", err)
	}
	return nil
}

// GetByReporter returns every report filed by the given reporter. Returns
// an empty slice (not nil) when the reporter has filed none.
func (s *ReportStore) GetByReporter(ctx context.Context, reporterUUID string) ([]*messages.SpamReport, error) {
	reports := make([]*messages.SpamReport, 0)
	err := s.kv.Scan(ctx, reporterPrefix(reporterUUID), func(_ string, value []byte) error {
		var r messages.SpamReport
		if err := json.Unmarshal(value, &r); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "unmarshal", err)
		}
		reports = append(reports, &r)
		return nil
	})
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb reports: scan", err)
	}
	return reports, nil
}
