package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/jobs"
)

// Compile-time interface satisfaction check.
var _ jobs.Store = (*MemoryJobsStore)(nil)

// MemoryJobsStore implements jobs.Store with an in-process map.
// claimedAt tracks the wall-clock at which each Running row was
// claimed; RecoverStale uses it to re-queue rows whose worker
// crashed or otherwise never reported completion. Rows in a state
// other than Running carry the zero value.
type MemoryJobsStore struct {
	mu        sync.Mutex
	rows      map[string]*jobs.Job
	claimedAt map[string]time.Time
}

// NewMemoryJobsStore returns an empty store.
func NewMemoryJobsStore() *MemoryJobsStore {
	return &MemoryJobsStore{
		rows:      make(map[string]*jobs.Job),
		claimedAt: make(map[string]time.Time),
	}
}

// Enqueue commits job, assigning ID and CreatedAt when empty.
func (s *MemoryJobsStore) Enqueue(_ context.Context, job *jobs.Job) error {
	if job == nil {
		return jobs.ErrJobNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if job.ID == "" {
		id, err := generateJobID()
		if err != nil {
			return err
		}
		job.ID = id
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now().UTC()
	}
	if job.Status == 0 {
		job.Status = jobs.StatusPending
	}
	cp := *job
	s.rows[job.ID] = &cp
	return nil
}

// ClaimDue selects pending jobs whose FireAt <= now and transitions
// them to Running. When types is non-empty, only rows whose Type is
// in the set are eligible. Each claim is timestamped so RecoverStale
// can detect rows whose worker died mid-execution.
func (s *MemoryJobsStore) ClaimDue(_ context.Context, now time.Time, limit int, types ...string) ([]*jobs.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	allow := buildTypeFilter(types)
	var out []*jobs.Job
	for _, j := range s.rows {
		if len(out) >= limit {
			break
		}
		if j.Status != jobs.StatusPending {
			continue
		}
		if j.FireAt.After(now) {
			continue
		}
		if allow != nil {
			if _, ok := allow[j.Type]; !ok {
				continue
			}
		}
		j.Status = jobs.StatusRunning
		j.Attempts++
		s.claimedAt[j.ID] = now
		cp := *j
		out = append(out, &cp)
	}
	return out, nil
}

// buildTypeFilter returns a set keyed by type. Nil result means
// "no filter — accept every type".
func buildTypeFilter(types []string) map[string]struct{} {
	if len(types) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(types))
	for _, t := range types {
		out[t] = struct{}{}
	}
	return out
}

// MarkDone deletes the job by ID.
func (s *MemoryJobsStore) MarkDone(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, id)
	delete(s.claimedAt, id)
	return nil
}

// MarkFailed re-queues with linear backoff or marks Dead when the
// retry budget is exhausted.
func (s *MemoryJobsStore) MarkFailed(_ context.Context, id string, now time.Time, backoff time.Duration, maxAttempts int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.rows[id]
	if !ok {
		return jobs.ErrJobNotFound
	}
	delete(s.claimedAt, id)
	if j.Attempts >= maxAttempts {
		j.Status = jobs.StatusFailed
		return nil
	}
	j.Status = jobs.StatusPending
	j.FireAt = now.Add(time.Duration(j.Attempts) * backoff)
	return nil
}

// ResetToPending transitions a Running row back to Pending without
// bumping Attempts. Idempotent for missing or non-Running rows.
func (s *MemoryJobsStore) ResetToPending(_ context.Context, id string, fireAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.rows[id]
	if !ok {
		return nil
	}
	if j.Status != jobs.StatusRunning {
		return nil
	}
	j.Status = jobs.StatusPending
	j.FireAt = fireAt
	delete(s.claimedAt, id)
	return nil
}

// RecoverStale re-queues Running rows whose claim is older than
// olderThan. Returns the number of rows transitioned. A Running
// row with no recorded claim time (zero) is treated as stale —
// that state can only occur after an unclean shutdown.
func (s *MemoryJobsStore) RecoverStale(_ context.Context, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	recovered := 0
	for id, j := range s.rows {
		if j.Status != jobs.StatusRunning {
			continue
		}
		claimed, ok := s.claimedAt[id]
		if ok && !claimed.Before(olderThan) {
			continue
		}
		j.Status = jobs.StatusPending
		delete(s.claimedAt, id)
		recovered++
	}
	return recovered, nil
}

// Get returns a defensive copy of the job by ID.
func (s *MemoryJobsStore) Get(_ context.Context, id string) (*jobs.Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.rows[id]
	if !ok {
		return nil, jobs.ErrJobNotFound
	}
	cp := *j
	return &cp, nil
}

// generateJobID returns 16 random bytes hex-encoded — 32 chars,
// matching the format used by other go-signal opaque identifiers.
func generateJobID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
