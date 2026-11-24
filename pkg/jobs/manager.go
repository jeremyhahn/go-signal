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

// Handler runs a job's payload; an error triggers the Store's retry and dead-letter handling. Delivery is at least once, so handlers must be idempotent.
type Handler func(ctx context.Context, job *Job) error

// DefaultStaleClaimTimeout is the threshold past which a Running
// job is considered abandoned by its worker. Calibrated to be
// comfortably longer than any legitimate handler runtime.
const DefaultStaleClaimTimeout = 5 * time.Minute

// Manager dispatches due jobs by Type to registered handlers, e.g. mgr.Register("send-wakeup-push", h); mgr.RunOnce(ctx, time.Now(), 100).
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

// SetStaleClaimTimeout sets how long a Running job may run before RunOnce requeues it (default DefaultStaleClaimTimeout).
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

// registeredTypes returns the registered job types, or nil (meaning every type) when none are registered.
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

// RunOnce requeues stale Running jobs, then claims and dispatches up to BatchSize due jobs; it returns the number dispatched.
func (m *Manager) RunOnce(ctx context.Context, now time.Time) (int, error) {
	if recovered, err := m.store.RecoverStale(ctx, now.Add(-m.staleTimeout)); err != nil {
		m.logger.WarnContext(ctx, "scheduled jobs: stale recovery failed",
			slog.Any("error", err))
	} else if recovered > 0 {
		m.logger.InfoContext(ctx, "scheduled jobs: recovered stale running rows",
			slog.Int("recovered", recovered))
	}

	// Claim only registered types, so a Store shared between Managers hands each only its own jobs.
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
			// Release every claimed but undispatched job now; RecoverStale catches any this misses.
			m.releaseClaimedTail(jobs[i:])
			return processed, ctxErr
		}
		m.dispatch(ctx, job, now)
		processed++
	}
	return processed, nil
}

// releaseClaimedTail returns still-Running jobs to Pending, each with its own 5-second budget.
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
		// A cancelled context does not count as an attempt: requeue with a fresh context.
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
