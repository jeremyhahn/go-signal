package workers

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/robfig/cron/v3"
)

// Schedule describes how often a worker runs.
type Schedule string

// Special-case schedule values with sentinel meaning. Any other string is
// treated as a cron expression (see github.com/robfig/cron/v3 for
// supported formats).
const (
	// ScheduleContinuous fires the worker repeatedly. After each
	// successful Run the next call starts immediately; a Run that returns
	// an error triggers exponential backoff.
	ScheduleContinuous Schedule = "@continuous"

	// ScheduleOnDemand disables automatic scheduling. The worker is only
	// invoked via Scheduler.RunOnce.
	ScheduleOnDemand Schedule = "@on-demand"
)

// Worker is a single background job. Implementations must be safe to
// invoke multiple times, idempotent where possible, and responsive to
// context cancellation.
type Worker interface {
	// Name uniquely identifies the worker. It doubles as the lease key in
	// leader-elected deployments, so names must be stable across code
	// revisions.
	Name() string

	// Schedule reports when the worker should fire. See the Schedule
	// constants and the cron expression syntax above.
	Schedule() Schedule

	// Run executes a single invocation of the worker. Runs must respect
	// ctx cancellation — Scheduler.Stop calls Cancel on the context and
	// waits for in-flight runs to return.
	Run(ctx context.Context) error
}

// Leaser is the minimal interface the worker scheduler uses to coordinate
// execution across replicas. Implementations typically wrap a
// distributed lock from pkg/cache (Redis) or a qrdb lease primitive.
//
// A nil Leaser disables leader election, which is correct for
// single-instance deployments and tests.
type Leaser interface {
	// Acquire attempts to become leader for the given key for the given
	// TTL. It returns nil when acquired and a non-nil error (typically
	// [ErrLeaderElectionFailed]) when another replica holds the lease.
	Acquire(ctx context.Context, key string, ttl time.Duration) error

	// Release hands back the lease. Safe to call even if Acquire failed —
	// a non-holder release is a no-op.
	Release(ctx context.Context, key string) error
}

// ErrLeaderElectionFailed is the canonical error a Leaser returns when
// another replica holds the lease. It is not an error condition for the
// caller — it simply means the current instance should not run the
// worker this tick.
var ErrLeaderElectionFailed = errors.New("workers: leader election failed")

// Scheduler owns a cron engine and a set of registered workers.
type Scheduler struct {
	log        *slog.Logger
	cron       *cron.Cron
	leaser     Leaser
	leaseTTL   time.Duration
	workers    map[string]Worker
	continuous map[string]*continuousRunner
	mu         sync.Mutex
	running    atomic.Bool
	wg         sync.WaitGroup

	// stopCtx is derived from the context supplied to Start. Stop cancels
	// stopCtx so continuous runners can exit even when the caller's
	// original context is still alive. Without this, a Stop() before
	// the caller cancels its context would deadlock on wg.Wait.
	stopCtx    context.Context
	stopCancel context.CancelFunc
}

// Config controls Scheduler behaviour.
type Config struct {
	// Logger receives scheduling events. If nil, slog.Default is used.
	Logger *slog.Logger

	// Leaser gates execution to one replica at a time. If nil, every
	// replica runs every worker — correct for single-instance deployments
	// and tests, but not for production topologies.
	Leaser Leaser

	// LeaseTTL is how long an acquired lease is held before it must be
	// re-acquired. Defaults to 30s. Short TTLs increase failover speed at
	// the cost of more lock traffic.
	LeaseTTL time.Duration
}

// NewScheduler constructs a Scheduler with the given config.
func NewScheduler(cfg Config) *Scheduler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	ttl := cfg.LeaseTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Scheduler{
		log:        logger,
		cron:       cron.New(),
		leaser:     cfg.Leaser,
		leaseTTL:   ttl,
		workers:    make(map[string]Worker),
		continuous: make(map[string]*continuousRunner),
	}
}

// Register adds w to the scheduler. It must be called before Start.
// Registering two workers with the same Name returns an error.
func (s *Scheduler) Register(w Worker) error {
	if s.running.Load() {
		return errors.New("workers: cannot Register after Start")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.workers[w.Name()]; exists {
		return signalerrors.New(signalerrors.ErrAlreadyExists, "workers: duplicate worker "+strconv.Quote(w.Name()))
	}
	s.workers[w.Name()] = w
	return nil
}

// List returns all registered worker names, useful for admin CLIs.
func (s *Scheduler) List() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.workers))
	for name := range s.workers {
		names = append(names, name)
	}
	return names
}

// RunOnce executes a worker immediately, regardless of its schedule. It
// is used by admin CLIs (`signald workers run <name>`) and is the only
// way to invoke an on-demand worker.
//
// Leader election applies identically: if a Leaser is configured and
// another replica holds the lease, RunOnce returns ErrLeaderElectionFailed.
func (s *Scheduler) RunOnce(ctx context.Context, name string) error {
	s.mu.Lock()
	w, ok := s.workers[name]
	s.mu.Unlock()
	if !ok {
		return signalerrors.New(signalerrors.ErrNotFound, "workers: unknown worker "+strconv.Quote(name))
	}
	return s.runWithLease(ctx, w)
}

// Start wires registered workers into cron / continuous runners and
// kicks off the scheduler. Calling Start twice is a no-op; calling
// Register after Start is an error.
func (s *Scheduler) Start(ctx context.Context) error {
	if !s.running.CompareAndSwap(false, true) {
		return nil
	}

	// Derive a cancellable context so Stop can unblock continuous
	// runners without waiting for the caller's ctx to be cancelled.
	s.stopCtx, s.stopCancel = context.WithCancel(ctx)
	runnerCtx := s.stopCtx

	s.mu.Lock()
	for name, w := range s.workers {
		switch sch := w.Schedule(); sch {
		case ScheduleContinuous:
			r := &continuousRunner{parent: s, worker: w}
			s.continuous[name] = r
			s.wg.Add(1)
			go r.loop(runnerCtx)
		case ScheduleOnDemand:
			// do not register with cron.
		default:
			// Bind w to a closure so cron invokes this specific worker.
			worker := w
			if _, err := s.cron.AddFunc(string(sch), func() {
				if err := s.runWithLease(runnerCtx, worker); err != nil && !errors.Is(err, ErrLeaderElectionFailed) && runnerCtx.Err() == nil {
					s.log.Error("workers: scheduled run failed", "worker", worker.Name(), "err", err)
				}
			}); err != nil {
				s.mu.Unlock()
				s.stopCancel()
				return signalerrors.Wrap(signalerrors.ErrInternal, "workers: schedule "+strconv.Quote(name), err)
			}
		}
	}
	s.mu.Unlock()

	s.cron.Start()
	return nil
}

// Stop signals every continuous runner to exit and waits for them to
// return. It also stops the cron engine. Safe to call even if Start was
// never invoked.
func (s *Scheduler) Stop() {
	if !s.running.CompareAndSwap(true, false) {
		return
	}
	if s.stopCancel != nil {
		s.stopCancel()
	}
	ctxStop := s.cron.Stop()
	<-ctxStop.Done()
	s.wg.Wait()
}

// runWithLease acquires the Leaser (if any), runs the worker, and
// releases. The Release call uses a fresh detached context so a
// cancelled ctx does not leak a held lease.
func (s *Scheduler) runWithLease(ctx context.Context, w Worker) error {
	if s.leaser != nil {
		if err := s.leaser.Acquire(ctx, w.Name(), s.leaseTTL); err != nil {
			return err
		}
		defer func() {
			releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.leaser.Release(releaseCtx, w.Name())
		}()
	}
	start := time.Now()
	err := w.Run(ctx)
	s.log.Info("workers: run complete", "worker", w.Name(), "duration", time.Since(start), "err", err)
	return err
}

// continuousRunner drives a ScheduleContinuous worker in a loop with
// exponential backoff on error.
type continuousRunner struct {
	parent *Scheduler
	worker Worker
}

func (r *continuousRunner) loop(ctx context.Context) {
	defer r.parent.wg.Done()
	const (
		minBackoff = 100 * time.Millisecond
		maxBackoff = 30 * time.Second
		// idleYield is the minimum pause between successful invocations.
		// It prevents a Run that returns instantly from pegging a CPU
		// core. Real workers that block internally (BLPOP etc.) won't
		// notice it; no-op or ready-queue workers will.
		idleYield = time.Millisecond
	)
	backoff := minBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		err := r.parent.runWithLease(ctx, r.worker)
		if errors.Is(err, ErrLeaderElectionFailed) {
			// Another instance is leader; back off more aggressively so we
			// don't hammer the lease.
			if wait := sleepCtx(ctx, r.parent.leaseTTL); wait {
				return
			}
			continue
		}
		if err != nil {
			r.parent.log.Error("workers: continuous run failed", "worker", r.worker.Name(), "err", err, "backoff", backoff)
			if wait := sleepCtx(ctx, backoff); wait {
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = minBackoff
		if wait := sleepCtx(ctx, idleYield); wait {
			return
		}
	}
}

// sleepCtx sleeps for d or until ctx is cancelled. Returns true when
// ctx was cancelled (caller should abort).
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() != nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return false
	case <-ctx.Done():
		return true
	}
}
