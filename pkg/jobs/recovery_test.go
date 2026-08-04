package jobs

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// claimTrackingStore wraps fakeStore-style semantics but records
// every ResetToPending call so the C1 fix can be asserted.
type claimTrackingStore struct {
	mu             sync.Mutex
	rows           map[string]*Job
	claimedAt      map[string]time.Time
	resetCalls     []string
	recoverCalls   int
	enqueueCounter int
}

func newClaimTrackingStore() *claimTrackingStore {
	return &claimTrackingStore{
		rows:      make(map[string]*Job),
		claimedAt: make(map[string]time.Time),
	}
}

func (s *claimTrackingStore) Enqueue(_ context.Context, j *Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j.ID == "" {
		s.enqueueCounter++
		j.ID = "id-" + time.Now().Format("150405.000000000")
	}
	if j.Status == 0 {
		j.Status = StatusPending
	}
	cp := *j
	s.rows[j.ID] = &cp
	return nil
}

func (s *claimTrackingStore) ClaimDue(_ context.Context, now time.Time, limit int, _ ...string) ([]*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Job
	for _, j := range s.rows {
		if j.Status != StatusPending || j.FireAt.After(now) {
			continue
		}
		j.Status = StatusRunning
		j.Attempts++
		s.claimedAt[j.ID] = now
		cp := *j
		out = append(out, &cp)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *claimTrackingStore) MarkDone(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, id)
	delete(s.claimedAt, id)
	return nil
}

func (s *claimTrackingStore) MarkFailed(_ context.Context, id string, now time.Time, backoff time.Duration, maxAttempts int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.rows[id]
	if !ok {
		return ErrJobNotFound
	}
	if j.Attempts >= maxAttempts {
		j.Status = StatusFailed
	} else {
		j.Status = StatusPending
		j.FireAt = now.Add(time.Duration(j.Attempts) * backoff)
	}
	delete(s.claimedAt, id)
	return nil
}

func (s *claimTrackingStore) ResetToPending(_ context.Context, id string, fireAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetCalls = append(s.resetCalls, id)
	j, ok := s.rows[id]
	if !ok || j.Status != StatusRunning {
		return nil
	}
	j.Status = StatusPending
	j.FireAt = fireAt
	delete(s.claimedAt, id)
	return nil
}

func (s *claimTrackingStore) RecoverStale(_ context.Context, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recoverCalls++
	n := 0
	for id, j := range s.rows {
		if j.Status != StatusRunning {
			continue
		}
		claimed, ok := s.claimedAt[id]
		if ok && !claimed.Before(olderThan) {
			continue
		}
		j.Status = StatusPending
		delete(s.claimedAt, id)
		n++
	}
	return n, nil
}

func (s *claimTrackingStore) Get(_ context.Context, id string) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.rows[id]
	if !ok {
		return nil, ErrJobNotFound
	}
	cp := *j
	return &cp, nil
}

func TestManager_RunOnce_CallsRecoverStaleAtHead(t *testing.T) {
	s := newClaimTrackingStore()
	mgr := newQuietManager(s)
	if _, err := mgr.RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	s.mu.Lock()
	calls := s.recoverCalls
	s.mu.Unlock()
	if calls != 1 {
		t.Errorf("RecoverStale calls = %d, want 1", calls)
	}
}

func TestManager_HandlerCtxCancel_ResetsToPending(t *testing.T) {
	s := newClaimTrackingStore()
	_ = s.Enqueue(context.Background(), &Job{Type: "slow", FireAt: time.Now().Add(-time.Second)})

	mgr := newQuietManager(s)
	mgr.Register("slow", func(_ context.Context, _ *Job) error {
		return context.Canceled
	})
	if _, err := mgr.RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.resetCalls) != 1 {
		t.Fatalf("expected 1 ResetToPending call, got %d", len(s.resetCalls))
	}
	for _, j := range s.rows {
		if j.Status != StatusPending {
			t.Errorf("job status post-cancel = %v, want Pending", j.Status)
		}
	}
}

func TestManager_RunOnce_ReleasesUnprocessedOnCtxCancel(t *testing.T) {
	s := newClaimTrackingStore()
	// Two due jobs; the handler cancels the parent context during
	// the first dispatch so the second goes back to Pending via
	// the releaseClaimedTail path.
	_ = s.Enqueue(context.Background(), &Job{Type: "a", FireAt: time.Now().Add(-time.Second)})
	_ = s.Enqueue(context.Background(), &Job{Type: "a", FireAt: time.Now().Add(-time.Second)})

	mgr := newQuietManager(s)
	ctx, cancel := context.WithCancel(context.Background())
	mgr.Register("a", func(_ context.Context, _ *Job) error {
		cancel()
		return nil
	})
	_, err := mgr.RunOnce(ctx, time.Now())
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	// After RunOnce, every claimed-but-not-dispatched job must be
	// back to Pending. The cancelled-during-handler one is removed
	// by MarkDone; the second one stays in the store as Pending.
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := 0
	for _, j := range s.rows {
		if j.Status == StatusPending {
			pending++
		}
	}
	if pending != 1 {
		t.Errorf("expected 1 row Pending post-cancel, got %d (rows=%d)", pending, len(s.rows))
	}
}

func TestManager_SetStaleClaimTimeout_BoundedThreshold(t *testing.T) {
	s := newClaimTrackingStore()
	mgr := newQuietManager(s)
	mgr.SetStaleClaimTimeout(0) // should be ignored
	if mgr.staleTimeout != DefaultStaleClaimTimeout {
		t.Errorf("zero override should keep default, got %v", mgr.staleTimeout)
	}
	mgr.SetStaleClaimTimeout(15 * time.Second)
	if mgr.staleTimeout != 15*time.Second {
		t.Errorf("override = %v, want 15s", mgr.staleTimeout)
	}
}
