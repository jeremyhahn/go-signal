package messages

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

const (
	// reportKeyPrefix is the KV key prefix for spam reports stored by ID.
	reportKeyPrefix = "signal/reports/"
	// reportByReporterPrefix is the KV key prefix for the reporter secondary index.
	reportByReporterPrefix = "signal/reports-by-reporter/"
)

// Compile-time assertion that KVReportStore satisfies ReportStore.
var _ ReportStore = (*KVReportStore)(nil)

// reportMarshal is a test seam for KVReportStore.Store's marshal-error branch.
var reportMarshal func(v any) ([]byte, error) = json.Marshal

// KVReportStore stores JSON reports at "signal/reports/{id}" and copies at "signal/reports-by-reporter/{reporterUUID}/{id}" for prefix scans; safe for concurrent use.
type KVReportStore struct {
	kv        store.KVClient
	idCounter atomic.Uint64
}

// NewKVReportStore creates a new KV-backed ReportStore backed by the given
// KVClient. The caller retains ownership of kv; NewKVReportStore does not
// close it.
func NewKVReportStore(kv store.KVClient) *KVReportStore {
	return &KVReportStore{kv: kv}
}

// Store assigns the report ID (and timestamp when zero) and writes the primary and reporter-index keys; a failure is *ReportStoreError.
func (s *KVReportStore) Store(ctx context.Context, report *SpamReport) error {
	id := s.nextID()
	report.ID = id
	if report.Timestamp.IsZero() {
		report.Timestamp = time.Now().UTC()
	}

	data, err := reportMarshal(report)
	if err != nil {
		return &ReportStoreError{Operation: "marshal", Cause: err}
	}

	primaryKey := reportKeyPrefix + id
	if err := s.kv.Put(ctx, primaryKey, data); err != nil {
		return &ReportStoreError{Operation: "put", Cause: err}
	}

	// The index entry stores the full payload so GetByReporter can decode each
	// record from the Scan callback without a secondary Get.
	indexKey := reportByReporterPrefix + report.ReporterUUID + "/" + id
	if err := s.kv.Put(ctx, indexKey, data); err != nil {
		return &ReportStoreError{Operation: "put-index", Cause: err}
	}

	return nil
}

// GetByReporter returns all spam reports filed by the given account UUID in
// key-sorted order. It returns an empty (non-nil) slice when no reports exist
// for the reporter.
func (s *KVReportStore) GetByReporter(ctx context.Context, reporterUUID string) ([]*SpamReport, error) {
	prefix := reportByReporterPrefix + reporterUUID + "/"
	var results []*SpamReport

	err := s.kv.Scan(ctx, prefix, func(_ string, value []byte) error {
		var report SpamReport
		if err := json.Unmarshal(value, &report); err != nil {
			return &ReportStoreError{Operation: "unmarshal", Cause: err}
		}
		results = append(results, &report)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if results == nil {
		results = []*SpamReport{}
	}
	return results, nil
}

// nextID returns a unique, monotonically increasing string report ID using a
// lock-free atomic counter.
func (s *KVReportStore) nextID() string {
	n := s.idCounter.Add(1)
	return "rpt-" + uitoa(n)
}

// uitoa converts a uint64 to its decimal string representation without
// importing strconv, keeping the dependency surface minimal for this helper.
func uitoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte(n%10) + '0'
		n /= 10
	}
	return string(buf[pos:])
}

// ReportStoreError is a report-store KV failure; Operation names the step and Cause unwraps.
type ReportStoreError struct {
	Operation string
	Cause     error
}

// Error implements the error interface.
func (e *ReportStoreError) Error() string {
	return "report store " + e.Operation + " error: " + e.Cause.Error()
}

// Unwrap returns the underlying cause, enabling errors.Is and errors.As.
func (e *ReportStoreError) Unwrap() error {
	return e.Cause
}
