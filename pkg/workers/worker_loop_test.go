package workers

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// flakyWorker returns err the first failN times, then returns nil.
// Used to drive the continuous runner through the error-backoff path
// and then recover.
type flakyWorker struct {
	name     string
	failN    int
	attempts atomic.Int64
	done     chan struct{}
}

func (w *flakyWorker) Name() string       { return w.name }
func (w *flakyWorker) Schedule() Schedule { return ScheduleContinuous }
func (w *flakyWorker) Run(ctx context.Context) error {
	n := w.attempts.Add(1)
	if n <= int64(w.failN) {
		return errors.New("flaky failure")
	}
	// Signal once recovered.
	select {
	case w.done <- struct{}{}:
	default:
	}
	return nil
}

func TestContinuousLoop_ErrorBackoffThenRecovers(t *testing.T) {
	t.Parallel()
	w := &flakyWorker{name: "flaky", failN: 3, done: make(chan struct{}, 1)}
	s := NewScheduler(quietConfig())
	_ = s.Register(w)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	select {
	case <-w.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("flaky worker never recovered; attempts=%d", w.attempts.Load())
	}
	if w.attempts.Load() < int64(w.failN+1) {
		t.Fatalf("expected at least %d attempts, got %d", w.failN+1, w.attempts.Load())
	}
}

func TestContinuousLoop_LeaderElectionFailed_Backs_Off(t *testing.T) {
	t.Parallel()
	leaser := &recordingLeaser{acquireFn: func(key string) error { return ErrLeaderElectionFailed }}
	cfg := quietConfig()
	cfg.Leaser = leaser
	cfg.LeaseTTL = 20 * time.Millisecond
	s := NewScheduler(cfg)

	w := &testWorker{name: "leased-cont", schedule: ScheduleContinuous}
	_ = s.Register(w)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Let the loop run for a few lease-TTL cycles.
	time.Sleep(100 * time.Millisecond)
	s.Stop()

	// The worker should never have Run because every Acquire failed.
	if w.runs.Load() != 0 {
		t.Fatalf("worker must not run when lease acquisition fails; got %d runs", w.runs.Load())
	}
	// But Acquire should have been called several times.
	leaser.mu.Lock()
	defer leaser.mu.Unlock()
	if len(leaser.acquires) < 2 {
		t.Fatalf("expected multiple Acquire attempts, got %d", len(leaser.acquires))
	}
}
