// Package jobs implements the scheduled-jobs subsystem ported from
// Java Signal-Server's ProcessScheduledJobsServiceCommand. The
// subsystem lets producers (request handlers, other workers)
// schedule typed work to fire at a future point in time, and a
// continuous worker drains due jobs and dispatches them to per-type
// handlers.
//
// The persistence interface is intentionally narrow so memory,
// qrdb, and postgres backends share identical semantics:
//
//   - Enqueue commits a Job atomically.
//   - ClaimDue returns at most `limit` jobs whose fire_at is at or
//     before `now`, marks them as in-flight (status=running) under
//     a per-claim lease so a second worker doesn't double-execute,
//     and returns a slice the caller iterates.
//   - MarkDone removes a successfully executed job.
//   - MarkFailed bumps the attempts counter, reschedules fire_at,
//     and either re-queues (Status=pending) or marks the job as
//     dead (Status=failed) when MaxAttempts is exceeded.
//
// Idempotency: handlers must be safe to re-run because a crash
// between MarkDone/MarkFailed and the next ClaimDue tick can replay
// a job. Mirrors Java's at-least-once contract.
package jobs

import (
	"context"
	"errors"
	"time"
)

// Status enumerates the lifecycle states of a scheduled job.
type Status int

const (
	// StatusPending means the job is queued and waiting for its
	// fire_at moment.
	StatusPending Status = iota + 1
	// StatusRunning means a worker has claimed the job and is
	// executing it. ClaimDue → handler dispatch sets this state;
	// MarkDone removes the row; MarkFailed rolls back to Pending
	// (with a new fire_at) or Dead.
	StatusRunning
	// StatusFailed means the job exceeded its retry budget. Rows
	// stay in this state for operator inspection; they are not
	// reclaimed by ClaimDue.
	StatusFailed
)

// DefaultMaxAttempts caps retries at 5 — matches Java's
// ProcessScheduledJobsServiceCommand RETRY_LIMIT.
const DefaultMaxAttempts = 5

// DefaultBackoff is the base interval applied to fire_at when a
// failed job is re-queued. The actual delay is attempts × backoff.
const DefaultBackoff = 30 * time.Second

// Job represents one scheduled unit of work.
type Job struct {
	// ID is a server-assigned opaque identifier. Implementations may
	// use any unique encoding; callers treat it as opaque.
	ID string
	// Type is the handler key. The dispatcher looks up the
	// registered handler by exact match.
	Type string
	// FireAt is the wall-clock UTC time at which the job becomes
	// eligible for ClaimDue.
	FireAt time.Time
	// Payload is the handler-defined opaque bytes. The dispatcher
	// hands it to the handler verbatim — typically a marshalled
	// protobuf or JSON.
	Payload []byte
	// Status is the lifecycle state. ClaimDue, MarkDone, MarkFailed
	// transition it.
	Status Status
	// Attempts is the number of times ClaimDue has handed the job
	// to a worker. Bumped by MarkFailed.
	Attempts int
	// CreatedAt is the wall-clock UTC time at which Enqueue
	// committed the job. Useful for monitoring and TTL sweeps.
	CreatedAt time.Time
}

// Store persists scheduled jobs.
type Store interface {
	// Enqueue commits job. The implementation populates ID and
	// CreatedAt before returning if they are empty; callers that
	// supply explicit values get them honored.
	Enqueue(ctx context.Context, job *Job) error

	// ClaimDue returns up to limit pending jobs whose FireAt is at
	// or before now AND whose Type appears in `types` (empty
	// `types` means "every type"). Each returned job is atomically
	// transitioned to Running so a concurrent worker does not
	// double-claim. The caller MUST follow up with either MarkDone
	// or MarkFailed for every returned job.
	//
	// The Type filter exists so two Manager instances backed by
	// the same Store can stay in their lanes — the APN worker's
	// Manager only ever sees JobTypeAPNPushSend rows, and the
	// general worker's Manager sees everything else.
	ClaimDue(ctx context.Context, now time.Time, limit int, types ...string) ([]*Job, error)

	// MarkDone removes the job by ID. Idempotent.
	MarkDone(ctx context.Context, id string) error

	// MarkFailed records a handler failure. When the job's Attempts
	// (after this call) is still below maxAttempts, the row is
	// re-queued (Status=Pending) with a fresh FireAt = now +
	// attempts*backoff. Otherwise the row is left in Status=Failed
	// for operator inspection.
	MarkFailed(ctx context.Context, id string, now time.Time, backoff time.Duration, maxAttempts int) error

	// ResetToPending transitions a Running job back to Pending
	// without bumping Attempts. Used when the dispatcher learns
	// (via context cancellation) that the handler did not run to
	// completion AND it was not the handler's fault. fireAt
	// controls when the job becomes eligible for ClaimDue again —
	// callers usually pass `time.Now()` so the next tick re-claims.
	// Missing or non-Running rows return without error
	// (idempotent — the recovery path may race with MarkDone).
	ResetToPending(ctx context.Context, id string, fireAt time.Time) error

	// RecoverStale re-queues every job whose Status is Running and
	// whose claim happened before `olderThan` (typically `now -
	// max plausible handler runtime`; 5 minutes is a safe default).
	// Returns the number of rows transitioned back to Pending.
	// Designed to be called at the head of every RunOnce so that
	// jobs stranded by a process crash always recover, regardless
	// of what the previous worker died doing.
	//
	// Implementations track claim time as a side effect of
	// ClaimDue. The contract is at-least-once delivery: a job
	// recovered by this method may run more than once if the
	// original handler had already finished but the bookkeeping
	// commit never landed. Handlers are required to be idempotent
	// (see package docs).
	RecoverStale(ctx context.Context, olderThan time.Time) (int, error)

	// Get returns the job by ID. Useful for tests and admin tools;
	// the dispatcher itself does not call it.
	Get(ctx context.Context, id string) (*Job, error)
}

// ErrJobNotFound is returned by Get when the supplied ID is not in
// the store. Implementations also surface it from MarkDone and
// MarkFailed when the row has already been swept.
var ErrJobNotFound = errors.New("jobs: not found")
