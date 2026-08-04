package jobs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// fakeStore is an in-memory jobs.Store used only for these tests so
// the manager's behavior can be asserted without depending on any
// backend package.
type fakeStore struct {
	mu       sync.Mutex
	rows     map[string]*Job
	nextID   int
	enqueue  error
	claim    error
	markDone func(id string) error
	failures []string
}

func newFakeStore() *fakeStore { return &fakeStore{rows: make(map[string]*Job)} }

func (s *fakeStore) Enqueue(_ context.Context, j *Job) error {
	if s.enqueue != nil {
		return s.enqueue
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if j.ID == "" {
		s.nextID++
		j.ID = "id-" + string(rune('a'+s.nextID-1))
	}
	if j.CreatedAt.IsZero() {
		j.CreatedAt = time.Now().UTC()
	}
	if j.Status == 0 {
		j.Status = StatusPending
	}
	cp := *j
	s.rows[j.ID] = &cp
	return nil
}

func (s *fakeStore) ClaimDue(_ context.Context, now time.Time, limit int, _ ...string) ([]*Job, error) {
	if s.claim != nil {
		return nil, s.claim
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Job
	for _, j := range s.rows {
		if j.Status != StatusPending {
			continue
		}
		if j.FireAt.After(now) {
			continue
		}
		j.Status = StatusRunning
		j.Attempts++
		cp := *j
		out = append(out, &cp)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *fakeStore) MarkDone(_ context.Context, id string) error {
	if s.markDone != nil {
		return s.markDone(id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, id)
	return nil
}

func (s *fakeStore) MarkFailed(_ context.Context, id string, now time.Time, backoff time.Duration, maxAttempts int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, id)
	j, ok := s.rows[id]
	if !ok {
		return ErrJobNotFound
	}
	if j.Attempts >= maxAttempts {
		j.Status = StatusFailed
		return nil
	}
	j.Status = StatusPending
	j.FireAt = now.Add(time.Duration(j.Attempts) * backoff)
	return nil
}

func (s *fakeStore) Get(_ context.Context, id string) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.rows[id]
	if !ok {
		return nil, ErrJobNotFound
	}
	cp := *j
	return &cp, nil
}

func (s *fakeStore) ResetToPending(_ context.Context, id string, fireAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.rows[id]
	if !ok || j.Status != StatusRunning {
		return nil
	}
	j.Status = StatusPending
	j.FireAt = fireAt
	return nil
}

func (s *fakeStore) RecoverStale(_ context.Context, olderThan time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, j := range s.rows {
		if j.Status == StatusRunning {
			j.Status = StatusPending
			n++
		}
	}
	return n, nil
}

func newQuietManager(store Store) *Manager {
	return NewManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestManager_DispatchesEachClaimedJob(t *testing.T) {
	s := newFakeStore()
	_ = s.Enqueue(context.Background(), &Job{Type: "test", FireAt: time.Now().Add(-time.Second)})
	_ = s.Enqueue(context.Background(), &Job{Type: "test", FireAt: time.Now().Add(-time.Second)})

	got := 0
	mgr := newQuietManager(s)
	mgr.Register("test", func(_ context.Context, _ *Job) error {
		got++
		return nil
	})
	n, err := mgr.RunOnce(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 2 || got != 2 {
		t.Errorf("n=%d got=%d, want 2/2", n, got)
	}
	if len(s.rows) != 0 {
		t.Errorf("expected 0 rows after MarkDone, got %d", len(s.rows))
	}
}

func TestManager_HandlerErrorTriggersMarkFailed(t *testing.T) {
	s := newFakeStore()
	_ = s.Enqueue(context.Background(), &Job{Type: "boom", FireAt: time.Now().Add(-time.Second)})
	mgr := newQuietManager(s)
	mgr.Register("boom", func(_ context.Context, _ *Job) error {
		return errors.New("handler failed")
	})
	if _, err := mgr.RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(s.failures) != 1 {
		t.Errorf("expected 1 MarkFailed call, got %d", len(s.failures))
	}
}

func TestManager_MissingHandlerTriggersMarkFailed(t *testing.T) {
	s := newFakeStore()
	_ = s.Enqueue(context.Background(), &Job{Type: "unknown", FireAt: time.Now().Add(-time.Second)})
	mgr := newQuietManager(s)
	if _, err := mgr.RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(s.failures) != 1 {
		t.Errorf("expected 1 MarkFailed call, got %d", len(s.failures))
	}
}

func TestManager_HandlerPanicConvertedToError(t *testing.T) {
	s := newFakeStore()
	_ = s.Enqueue(context.Background(), &Job{Type: "panicker", FireAt: time.Now().Add(-time.Second)})
	mgr := newQuietManager(s)
	mgr.Register("panicker", func(_ context.Context, _ *Job) error {
		panic("nope")
	})
	if _, err := mgr.RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(s.failures) != 1 {
		t.Errorf("panic should funnel to MarkFailed; got %d", len(s.failures))
	}
}

func TestManager_FutureJobNotClaimed(t *testing.T) {
	s := newFakeStore()
	_ = s.Enqueue(context.Background(), &Job{Type: "later", FireAt: time.Now().Add(time.Hour)})
	mgr := newQuietManager(s)
	mgr.Register("later", func(_ context.Context, _ *Job) error { return nil })
	n, err := mgr.RunOnce(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 jobs claimed when none are due, got %d", n)
	}
}

func TestManager_NilStoreError_NotCalled(t *testing.T) {
	s := newFakeStore()
	s.claim = errors.New("backend down")
	mgr := newQuietManager(s)
	mgr.Register("t", func(_ context.Context, _ *Job) error { return nil })
	if _, err := mgr.RunOnce(context.Background(), time.Now()); err == nil {
		t.Error("expected error when claim fails")
	}
}

func TestManager_ContextCancellationStopsLoop(t *testing.T) {
	s := newFakeStore()
	for i := 0; i < 5; i++ {
		_ = s.Enqueue(context.Background(), &Job{Type: "blocker", FireAt: time.Now().Add(-time.Second)})
	}
	mgr := newQuietManager(s)
	mgr.SetBatchSize(5)
	ctx, cancel := context.WithCancel(context.Background())
	mgr.Register("blocker", func(ctx context.Context, _ *Job) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	})
	if _, err := mgr.RunOnce(ctx, time.Now()); err == nil {
		t.Error("expected ctx-cancelled error")
	}
}

func TestNewManager_NilLogger_UsesDefault(t *testing.T) {
	// nil logger should fall back to slog.Default() without panicking.
	mgr := NewManager(newFakeStore(), nil)
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	if mgr.logger == nil {
		t.Error("logger should not be nil after nil-fallback")
	}
}

func TestManager_SetMaxAttempts(t *testing.T) {
	mgr := newQuietManager(newFakeStore())
	mgr.SetMaxAttempts(10)
	if mgr.maxRetry != 10 {
		t.Errorf("maxRetry = %d, want 10", mgr.maxRetry)
	}
}

func TestManager_SetBackoff(t *testing.T) {
	mgr := newQuietManager(newFakeStore())
	mgr.SetBackoff(5 * time.Minute)
	if mgr.backoff != 5*time.Minute {
		t.Errorf("backoff = %v, want 5m", mgr.backoff)
	}
}

func TestManager_Enqueue_DelegatesToStore(t *testing.T) {
	s := newFakeStore()
	mgr := newQuietManager(s)
	job := &Job{Type: "x", FireAt: time.Now().Add(time.Hour)}
	if err := mgr.Enqueue(context.Background(), job); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if job.ID == "" {
		t.Error("Enqueue must assign an ID")
	}
	s.mu.Lock()
	_, ok := s.rows[job.ID]
	s.mu.Unlock()
	if !ok {
		t.Error("job not in store after Enqueue")
	}
}

func TestManager_MarkDone_Error_Logged(t *testing.T) {
	s := newFakeStore()
	s.markDone = func(id string) error { return errors.New("MarkDone fail") }
	_ = s.Enqueue(context.Background(), &Job{Type: "ok", FireAt: time.Now().Add(-time.Second)})
	mgr := newQuietManager(s)
	mgr.Register("ok", func(_ context.Context, _ *Job) error { return nil })
	// Should not return an error even though MarkDone fails (just logs).
	if _, err := mgr.RunOnce(context.Background(), time.Now()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
}

func TestManager_RunOnce_RecoverStaleFailure_Continues(t *testing.T) {
	// RecoverStale failing should not abort the run — it logs a warning
	// and continues to ClaimDue.
	s := &failRecoverStore{fakeStore: newFakeStore()}
	_ = s.Enqueue(context.Background(), &Job{Type: "job", FireAt: time.Now().Add(-time.Second)})
	mgr := newQuietManager(s)
	mgr.Register("job", func(_ context.Context, _ *Job) error { return nil })
	n, err := mgr.RunOnce(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("RunOnce should continue despite RecoverStale error: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 job processed, got %d", n)
	}
}

// failRecoverStore wraps fakeStore but makes RecoverStale return an error.
type failRecoverStore struct{ *fakeStore }

func (f *failRecoverStore) RecoverStale(_ context.Context, _ time.Time) (int, error) {
	return 0, errors.New("recover stale failed")
}
