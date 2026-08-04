package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// Handler executes the payload of a scheduled job. Returning a
// non-nil error triggers the Store's MarkFailed retry/dead-letter
// machinery. nil returns trigger MarkDone.
//
// Handlers must be safe to re-run because the at-least-once delivery
// model means a crash between handler return and Store mutation
// re-delivers the job on the next tick.
type Handler func(ctx context.Context, job *Job) error

// DefaultStaleClaimTimeout is the threshold past which a Running
// job is considered abandoned by its worker. Calibrated to be
// comfortably longer than any legitimate handler runtime.
const DefaultStaleClaimTimeout = 5 * time.Minute

// Manager dispatches scheduled jobs by Type to registered handlers.
// Typical lifecycle:
//
//	mgr := jobs.NewManager(store, slog.Default())
//	mgr.Register("send-wakeup-push", sendWakeupHandler)
//	mgr.RunOnce(ctx, time.Now(), 100) // worker calls this on a cron
type Manager struct {
	store        Store
	logger       *slog.Logger
	mu           sync.RWMutex
	handlers     map[string]Handler
	maxRetry     int
	backoff      time.Duration
	maxBatch     int
	staleTimeout time.Duration
}

// NewManager constructs a Manager.
func NewManager(store Store, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		store:        store,
		logger:       logger,
		handlers:     make(map[string]Handler),
		maxRetry:     DefaultMaxAttempts,
		backoff:      DefaultBackoff,
		maxBatch:     100,
		staleTimeout: DefaultStaleClaimTimeout,
	}
}

// SetMaxAttempts overrides the retry budget. Default is
// DefaultMaxAttempts.
func (m *Manager) SetMaxAttempts(n int) { m.maxRetry = n }

// SetBackoff overrides the linear backoff base. Default is
// DefaultBackoff. The actual delay applied is attempts*backoff.
func (m *Manager) SetBackoff(d time.Duration) { m.backoff = d }

// SetBatchSize overrides the per-tick claim limit. Default is 100.
func (m *Manager) SetBatchSize(n int) { m.maxBatch = n }

// SetStaleClaimTimeout overrides the threshold used by RunOnce's
// recovery sweep. Default is DefaultStaleClaimTimeout (5 minutes).
// Operators with handlers that legitimately exceed 5m must raise
// this so live work isn't double-dispatched.
func (m *Manager) SetStaleClaimTimeout(d time.Duration) {
	if d > 0 {
		m.staleTimeout = d
	}
}

// Register associates a handler with a job type. Registering the
// same type twice replaces the prior handler.
func (m *Manager) Register(jobType string, fn Handler) {
	m.mu.Lock()
	m.handlers[jobType] = fn
	m.mu.Unlock()
}

// registeredTypes returns the snapshot of registered job types, in
// undefined order. Returns nil when no handlers have been registered
// so the Store ClaimDue contract degrades to "every type" — useful
// for tests that want a Manager to drain every row.
func (m *Manager) registeredTypes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.handlers) == 0 {
		return nil
	}
	out := make([]string, 0, len(m.handlers))
	for t := range m.handlers {
		out = append(out, t)
	}
	return out
}

// Enqueue is a convenience that delegates to the store. Defined on
// the manager so callers don't need to thread the store separately.
func (m *Manager) Enqueue(ctx context.Context, job *Job) error {
	return m.store.Enqueue(ctx, job)
}

// RunOnce sweeps stale Running rows back to Pending, claims up to
// BatchSize due jobs, and dispatches each. The scheduled-jobs
// worker calls this on every continuous tick. Returns (processed,
// error). processed counts both successful and failed dispatches.
//
// The recovery sweep at the head of each tick is what makes
// at-least-once delivery survive process crashes: any row stranded
// in Running because its worker died (or was SIGKILLed) gets
// re-queued for the next claim.
func (m *Manager) RunOnce(ctx context.Context, now time.Time) (int, error) {
	if recovered, err := m.store.RecoverStale(ctx, now.Add(-m.staleTimeout)); err != nil {
		m.logger.WarnContext(ctx, "scheduled jobs: stale recovery failed",
			slog.Any("error", err))
	} else if recovered > 0 {
		m.logger.InfoContext(ctx, "scheduled jobs: recovered stale running rows",
			slog.Int("recovered", recovered))
	}

	// Pass the registered types so a Store shared between Managers
	// hands each Manager only its own lanes. An unregistered job
	// type stays Pending until a Manager that knows it claims it.
	jobs, err := m.store.ClaimDue(ctx, now, m.maxBatch, m.registeredTypes()...)
	if err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "jobs: claim due", err)
	}
	if len(jobs) == 0 {
		return 0, nil
	}
	processed := 0
	for i, job := range jobs {
		if ctxErr := ctx.Err(); ctxErr != nil {
			// Release every job claimed but not yet
			// dispatched. The RecoverStale path at the head
			// of the next tick would catch them after the
			// stale timeout, but ResetToPending is
			// immediate — minimises retry latency. Errors
			// here are best-effort; RecoverStale is the
			// authoritative safety net.
			m.releaseClaimedTail(jobs[i:])
			return processed, ctxErr
		}
		m.dispatch(ctx, job, now)
		processed++
	}
	return processed, nil
}

// releaseClaimedTail flips every still-Running job in the supplied
// slice back to Pending. Each ResetToPending call gets its OWN
// 5-second budget — using a shared budget would let a degraded
// store strand every job past the first few. Failures fall through
// to RecoverStale on the next tick, which is the authoritative
// safety net.
func (m *Manager) releaseClaimedTail(remaining []*Job) {
	for _, job := range remaining {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := m.store.ResetToPending(ctx, job.ID, time.Now().UTC()); err != nil {
			m.logger.WarnContext(ctx, "scheduled jobs: reset on cancel failed",
				slog.String("id", job.ID),
				slog.Any("error", err))
		}
		cancel()
	}
}

// dispatch resolves the handler for job.Type and runs it. The result
// is funneled into MarkDone (success) or MarkFailed (handler error
// or missing handler).
func (m *Manager) dispatch(ctx context.Context, job *Job, now time.Time) {
	m.mu.RLock()
	handler := m.handlers[job.Type]
	m.mu.RUnlock()

	if handler == nil {
		m.logger.WarnContext(ctx, "scheduled job: no handler registered",
			slog.String("type", job.Type),
			slog.String("id", job.ID))
		_ = m.store.MarkFailed(ctx, job.ID, now, m.backoff, m.maxRetry)
		return
	}

	err := safeInvoke(ctx, handler, job)
	if err == nil {
		if doneErr := m.store.MarkDone(ctx, job.ID); doneErr != nil {
			m.logger.WarnContext(ctx, "scheduled job: MarkDone failed",
				slog.String("id", job.ID),
				slog.Any("error", doneErr))
		}
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		// Don't bump attempts when the context shut down — the job
		// did not get a fair chance to run. Flip it back to
		// Pending immediately so the next tick re-delivers it.
		// Use a fresh background context: the one that fired
		// would reject the ResetToPending call.
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if resetErr := m.store.ResetToPending(bg, job.ID, time.Now().UTC()); resetErr != nil {
			m.logger.WarnContext(bg, "scheduled job: reset-on-cancel failed",
				slog.String("id", job.ID),
				slog.Any("error", resetErr))
		}
		return
	}
	m.logger.WarnContext(ctx, "scheduled job: handler failed",
		slog.String("type", job.Type),
		slog.String("id", job.ID),
		slog.Int("attempts", job.Attempts),
		slog.Any("error", err))
	if failErr := m.store.MarkFailed(ctx, job.ID, now, m.backoff, m.maxRetry); failErr != nil {
		m.logger.WarnContext(ctx, "scheduled job: MarkFailed failed",
			slog.String("id", job.ID),
			slog.Any("error", failErr))
	}
}

// safeInvoke runs handler under a recover so a panic in one handler
// does not bring down the worker loop. Panics surface as errors and
// follow the MarkFailed retry path.
func safeInvoke(ctx context.Context, handler Handler, job *Job) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = signalerrors.New(signalerrors.ErrInternal, fmt.Sprintf("handler panic: %v", r))
		}
	}()
	return handler(ctx, job)
}
