package memory

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// Compile-time interface satisfaction check.
var _ messages.ReportStore = (*MemoryReportStore)(nil)

// MemoryReportStore implements messages.ReportStore with in-memory storage.
// All operations are safe for concurrent use; reads avoid holding a write
// lock by using a read-lock for GetByReporter.
type MemoryReportStore struct {
	mu         sync.RWMutex
	byID       map[string]*messages.SpamReport
	byReporter map[string][]*messages.SpamReport // reporterUUID -> reports
	idCounter  atomic.Uint64
}

// NewMemoryReportStore creates a new in-memory spam report store.
func NewMemoryReportStore() *MemoryReportStore {
	return &MemoryReportStore{
		byID:       make(map[string]*messages.SpamReport),
		byReporter: make(map[string][]*messages.SpamReport),
	}
}

// Store persists a spam report, assigning a unique ID and recording the
// current timestamp when the report's Timestamp is zero.
func (s *MemoryReportStore) Store(_ context.Context, report *messages.SpamReport) error {
	id := strconv.FormatUint(s.idCounter.Add(1), 10)

	clone := *report
	clone.ID = id
	if clone.Timestamp.IsZero() {
		clone.Timestamp = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.byID[id] = &clone
	s.byReporter[clone.ReporterUUID] = append(s.byReporter[clone.ReporterUUID], &clone)

	// Write the assigned ID back to the caller's struct so they can use it.
	report.ID = id
	if report.Timestamp.IsZero() {
		report.Timestamp = clone.Timestamp
	}

	return nil
}

// GetByReporter returns all spam reports filed by the given account UUID.
// Returns an empty (non-nil) slice when no reports exist.
func (s *MemoryReportStore) GetByReporter(_ context.Context, reporterUUID string) ([]*messages.SpamReport, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries := s.byReporter[reporterUUID]
	result := make([]*messages.SpamReport, len(entries))
	for i, r := range entries {
		clone := *r
		result[i] = &clone
	}

	return result, nil
}
