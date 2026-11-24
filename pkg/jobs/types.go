// Package jobs schedules typed work for a future time and dispatches due jobs to per-type handlers.
// Stores: Enqueue commits atomically, ClaimDue leases up to limit due jobs, MarkDone removes, MarkFailed re-queues or marks dead. Handlers must be idempotent (at-least-once).
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
	// StatusRunning means a worker has claimed the job; MarkDone removes it, MarkFailed returns it to Pending or Dead.
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

	// ClaimDue atomically moves up to limit due Pending jobs of the given types (all when empty) to Running; every returned job needs MarkDone or MarkFailed.
	ClaimDue(ctx context.Context, now time.Time, limit int, types ...string) ([]*Job, error)

	// MarkDone removes the job by ID. Idempotent.
	MarkDone(ctx context.Context, id string) error

	// MarkFailed re-queues the job at now + attempts*backoff below maxAttempts, else leaves it Failed.
	MarkFailed(ctx context.Context, id string, now time.Time, backoff time.Duration, maxAttempts int) error

	// ResetToPending returns a Running job to Pending at fireAt without counting an attempt; missing or non-Running rows are a no-op.
	ResetToPending(ctx context.Context, id string, fireAt time.Time) error

	// RecoverStale re-queues jobs claimed before olderThan and returns how many; call it at the head of every RunOnce.
	RecoverStale(ctx context.Context, olderThan time.Time) (int, error)

	// Get returns the job by ID. Useful for tests and admin tools;
	// the dispatcher itself does not call it.
	Get(ctx context.Context, id string) (*Job, error)
}

// ErrJobNotFound is returned by Get when the supplied ID is not in
// the store. Implementations also surface it from MarkDone and
// MarkFailed when the row has already been swept.
var ErrJobNotFound = errors.New("jobs: not found")
