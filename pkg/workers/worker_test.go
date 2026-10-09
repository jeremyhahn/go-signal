package workers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// quietConfig returns a Config with a discard logger so tests don't spam
// stderr when continuous workers run in tight loops.
func quietConfig() Config {
	return Config{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// testWorker is a minimal Worker used across scheduler tests.
type testWorker struct {
	name     string
	schedule Schedule
	runs     atomic.Int64
	err      error
	// runCh lets tests wait for a run. A non-nil runCh receives the
	// current run count each time Run is called.
	runCh chan int64
}

func (w *testWorker) Name() string       { return w.name }
func (w *testWorker) Schedule() Schedule { return w.schedule }
func (w *testWorker) Run(ctx context.Context) error {
	n := w.runs.Add(1)
	if w.runCh != nil {
		select {
		case w.runCh <- n:
		default:
		}
	}
	return w.err
}

// ---- Scheduler.Register -----

func TestScheduler_Register_SuccessAndDuplicate(t *testing.T) {
	t.Parallel()
	s := NewScheduler(quietConfig())
	if err := s.Register(&testWorker{name: "a", schedule: ScheduleOnDemand}); err != nil {
		t.Fatal(err)
	}
	if err := s.Register(&testWorker{name: "a", schedule: ScheduleOnDemand}); err == nil {
		t.Fatal("expected duplicate registration to fail")
	}
}

func TestScheduler_Register_AfterStart_Fails(t *testing.T) {
	t.Parallel()
	s := NewScheduler(quietConfig())
	_ = s.Register(&testWorker{name: "a", schedule: ScheduleOnDemand})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	if err := s.Register(&testWorker{name: "b", schedule: ScheduleOnDemand}); err == nil {
		t.Fatal("expected Register after Start to fail")
	}
}

// ---- Scheduler.List -----

func TestScheduler_List_ReturnsAllNames(t *testing.T) {
	t.Parallel()
	s := NewScheduler(quietConfig())
	for _, n := range []string{"x", "y", "z"} {
		if err := s.Register(&testWorker{name: n, schedule: ScheduleOnDemand}); err != nil {
			t.Fatal(err)
		}
	}
	names := s.List()
	if len(names) != 3 {
		t.Fatalf("expected 3 names, got %v", names)
	}
}

// ---- RunOnce -----

func TestScheduler_RunOnce_InvokesWorker(t *testing.T) {
	t.Parallel()
	s := NewScheduler(quietConfig())
	w := &testWorker{name: "once", schedule: ScheduleOnDemand}
	_ = s.Register(w)

	if err := s.RunOnce(context.Background(), "once"); err != nil {
		t.Fatal(err)
	}
	if w.runs.Load() != 1 {
		t.Fatalf("expected 1 run, got %d", w.runs.Load())
	}
}

func TestScheduler_RunOnce_UnknownWorker(t *testing.T) {
	t.Parallel()
	s := NewScheduler(quietConfig())
	if err := s.RunOnce(context.Background(), "absent"); err == nil {
		t.Fatal("expected error for unknown worker")
	}
}

func TestScheduler_RunOnce_WorkerError_Propagated(t *testing.T) {
	t.Parallel()
	s := NewScheduler(quietConfig())
	boom := errors.New("boom")
	_ = s.Register(&testWorker{name: "w", schedule: ScheduleOnDemand, err: boom})

	err := s.RunOnce(context.Background(), "w")
	if !errors.Is(err, boom) {
		t.Fatalf("expected wrapped worker error, got %v", err)
	}
}

// ---- Start / scheduled runs -----

func TestScheduler_Cron_FiresWorkerOnInterval(t *testing.T) {
	t.Parallel()
	w := &testWorker{
		name: "cron",
		// robfig/cron's ConstantDelaySchedule rounds any interval below
		// one second up to one second, so "@every 100ms" fires once per
		// second, not ten times. Use the real granularity explicitly.
		schedule: Schedule("@every 1s"),
		runCh:    make(chan int64, 4),
	}
	s := NewScheduler(quietConfig())
	_ = s.Register(w)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	// Two runs land at ~1s and ~2s after Start; allow the two periods
	// plus scheduling slack so a loaded host cannot race the second fire.
	deadline := time.After(2*time.Second + 2*time.Second)
	for got := 0; got < 2; {
		select {
		case <-w.runCh:
			got++
		case <-deadline:
			t.Fatalf("expected 2 cron runs, got %d", w.runs.Load())
		}
	}
}

func TestScheduler_Start_IsIdempotent(t *testing.T) {
	t.Parallel()
	s := NewScheduler(quietConfig())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// Second Start is a no-op.
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	s.Stop()
}

func TestScheduler_Stop_BeforeStart_IsSafe(t *testing.T) {
	t.Parallel()
	s := NewScheduler(quietConfig())
	s.Stop() // must not panic.
}

func TestScheduler_Start_InvalidCronSpec_Fails(t *testing.T) {
	t.Parallel()
	s := NewScheduler(quietConfig())
	_ = s.Register(&testWorker{name: "bad", schedule: Schedule("this is not a cron expression")})
	if err := s.Start(context.Background()); err == nil {
		t.Fatal("expected Start to fail on bad cron spec")
	}
}

// ---- Continuous workers -----

func TestScheduler_Continuous_RunsRepeatedly(t *testing.T) {
	t.Parallel()
	w := &testWorker{
		name:     "cont",
		schedule: ScheduleContinuous,
		runCh:    make(chan int64, 8),
	}
	s := NewScheduler(quietConfig())
	_ = s.Register(w)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	// Wait for several runs in a bounded time. Continuous runners invoke
	// Run as fast as possible after each success.
	deadline := time.After(2 * time.Second)
	for got := 0; got < 3; {
		select {
		case <-w.runCh:
			got++
		case <-deadline:
			t.Fatalf("expected 3 continuous runs, got %d", w.runs.Load())
		}
	}
}

func TestScheduler_Continuous_StopsOnCancel(t *testing.T) {
	t.Parallel()
	w := &testWorker{
		name:     "cont",
		schedule: ScheduleContinuous,
		runCh:    make(chan int64, 1),
	}
	s := NewScheduler(quietConfig())
	_ = s.Register(w)

	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for at least one run so we know the goroutine started, then
	// cancel and ensure Stop returns.
	<-w.runCh
	cancel()
	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return within 2s")
	}
}

// ---- Leader election -----

type recordingLeaser struct {
	mu        sync.Mutex
	acquires  []string
	releases  []string
	acquireFn func(key string) error
}

func (l *recordingLeaser) Acquire(ctx context.Context, key string, ttl time.Duration) error {
	l.mu.Lock()
	l.acquires = append(l.acquires, key)
	fn := l.acquireFn
	l.mu.Unlock()
	if fn != nil {
		return fn(key)
	}
	return nil
}

func (l *recordingLeaser) Release(ctx context.Context, key string) error {
	l.mu.Lock()
	l.releases = append(l.releases, key)
	l.mu.Unlock()
	return nil
}

func TestScheduler_RunWithLease_AcquiresAndReleases(t *testing.T) {
	t.Parallel()
	leaser := &recordingLeaser{}
	cfg := quietConfig()
	cfg.Leaser = leaser
	cfg.LeaseTTL = time.Second
	s := NewScheduler(cfg)
	_ = s.Register(&testWorker{name: "leased", schedule: ScheduleOnDemand})

	if err := s.RunOnce(context.Background(), "leased"); err != nil {
		t.Fatal(err)
	}

	leaser.mu.Lock()
	defer leaser.mu.Unlock()
	if len(leaser.acquires) != 1 || leaser.acquires[0] != "leased" {
		t.Fatalf("acquires=%v", leaser.acquires)
	}
	if len(leaser.releases) != 1 || leaser.releases[0] != "leased" {
		t.Fatalf("releases=%v", leaser.releases)
	}
}

func TestScheduler_RunWithLease_AcquireFails_SkipsWorker(t *testing.T) {
	t.Parallel()
	leaser := &recordingLeaser{acquireFn: func(key string) error { return ErrLeaderElectionFailed }}
	cfg := quietConfig()
	cfg.Leaser = leaser
	s := NewScheduler(cfg)
	w := &testWorker{name: "w", schedule: ScheduleOnDemand}
	_ = s.Register(w)

	err := s.RunOnce(context.Background(), "w")
	if !errors.Is(err, ErrLeaderElectionFailed) {
		t.Fatalf("expected ErrLeaderElectionFailed, got %v", err)
	}
	if w.runs.Load() != 0 {
		t.Fatal("worker must not run when lease acquisition fails")
	}
}
