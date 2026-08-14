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

// reportMarshal is the JSON marshalling function used by KVReportStore.Store.
// It is a package-level variable so tests can substitute a failing
// implementation to exercise the marshal-error branch, which is otherwise
// unreachable because SpamReport contains only JSON-serialisable field types.
var reportMarshal func(v any) ([]byte, error) = json.Marshal

// KVReportStore implements ReportStore using a pluggable KVClient backend.
// Reports are stored as JSON-encoded values under primary keys of the form
// "signal/reports/{id}". A secondary index keyed by
// "signal/reports-by-reporter/{reporterUUID}/{id}" stores the full report
// payload, enabling efficient prefix-scan lookup by reporter without an
// additional Get round-trip per record.
//
// All methods are safe for concurrent use. ID generation uses a lock-free
// monotonic counter via sync/atomic.
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

// Store persists a spam report to the KV store. The report's ID field is
// assigned by the store before writing. If report.Timestamp is zero the
// current UTC time is used. The report is written to both the primary key
// and a reporter secondary index in separate Put operations; if either fails
// a typed *ReportStoreError is returned.
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

// ReportStoreError indicates a KV operation failure within the report store.
// The Operation field names the failing step (e.g. "put", "put-index",
// "unmarshal"). Cause holds the underlying error and is surfaced via Unwrap
// for errors.Is / errors.As traversal.
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
