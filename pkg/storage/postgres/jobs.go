package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/jobs"
)

// JobsStore persists scheduled jobs to the `scheduled_jobs` table.
type JobsStore struct {
	q Querier
	c *Client
}

// Compile-time interface satisfaction check.
var _ jobs.Store = (*JobsStore)(nil)

// NewJobsStore returns a store backed by c.
func NewJobsStore(c *Client) *JobsStore {
	return &JobsStore{q: c.Pool(), c: c}
}

// Enqueue inserts the job, assigning ID + CreatedAt when empty.
func (s *JobsStore) Enqueue(ctx context.Context, job *jobs.Job) error {
	if job == nil {
		return jobs.ErrJobNotFound
	}
	if job.ID == "" {
		id, err := newJobID()
		if err != nil {
			return err
		}
		job.ID = id
	}
	if job.Status == 0 {
		job.Status = jobs.StatusPending
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now().UTC()
	}
	const stmt = `
		INSERT INTO scheduled_jobs (id, job_type, fire_at, payload, status, attempts, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.q.Exec(ctx, stmt,
		job.ID, job.Type, job.FireAt, job.Payload, int(job.Status), job.Attempts, job.CreatedAt)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres jobs: enqueue", err)
	}
	return nil
}

// ClaimDue atomically picks up to limit pending jobs whose fire_at
// is at or before now and transitions them to running. When types
// is non-empty the WHERE clause includes `job_type = ANY($4)` so
// each Manager instance only sees its own registered types. Uses
// SELECT ... FOR UPDATE SKIP LOCKED so concurrent workers don't
// collide on the same rows.
func (s *JobsStore) ClaimDue(ctx context.Context, now time.Time, limit int, types ...string) ([]*jobs.Job, error) {
	var out []*jobs.Job
	err := withTxQuerier(ctx, s.q, func(tx pgx.Tx) error {
		const selAll = `
			SELECT id, job_type, fire_at, payload, attempts, created_at
			FROM scheduled_jobs
			WHERE status = $1 AND fire_at <= $2
			ORDER BY fire_at
			LIMIT $3
			FOR UPDATE SKIP LOCKED`
		const selTyped = `
			SELECT id, job_type, fire_at, payload, attempts, created_at
			FROM scheduled_jobs
			WHERE status = $1 AND fire_at <= $2 AND job_type = ANY($4)
			ORDER BY fire_at
			LIMIT $3
			FOR UPDATE SKIP LOCKED`
		var rows pgx.Rows
		var err error
		if len(types) == 0 {
			rows, err = tx.Query(ctx, selAll, int(jobs.StatusPending), now, limit)
		} else {
			rows, err = tx.Query(ctx, selTyped, int(jobs.StatusPending), now, limit, types)
		}
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres jobs: select due", err)
		}
		ids := make([]string, 0, limit)
		for rows.Next() {
			j := &jobs.Job{Status: jobs.StatusRunning}
			if err := rows.Scan(&j.ID, &j.Type, &j.FireAt, &j.Payload, &j.Attempts, &j.CreatedAt); err != nil {
				rows.Close()
				return signalerrors.Wrap(signalerrors.ErrInternal, "postgres jobs: scan due", err)
			}
			j.Attempts++
			out = append(out, j)
			ids = append(ids, j.ID)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres jobs: rows due", err)
		}
		if len(ids) == 0 {
			return nil
		}
		const upd = `
			UPDATE scheduled_jobs
			SET status = $1, attempts = attempts + 1, claimed_at = $3
			WHERE id = ANY($2)`
		if _, err := tx.Exec(ctx, upd, int(jobs.StatusRunning), ids, now); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres jobs: claim update", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MarkDone deletes the job by ID.
func (s *JobsStore) MarkDone(ctx context.Context, id string) error {
	if _, err := s.q.Exec(ctx, `DELETE FROM scheduled_jobs WHERE id = $1`, id); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres jobs: mark done", err)
	}
	return nil
}

// MarkFailed re-queues with backoff or marks Failed when exhausted.
// Single atomic UPDATE so a concurrent reader either sees the
// pre-failure row or the post-failure row, never something in
// between.
func (s *JobsStore) MarkFailed(ctx context.Context, id string, now time.Time, backoff time.Duration, maxAttempts int) error {
	return withTxQuerier(ctx, s.q, func(tx pgx.Tx) error {
		var attempts int
		err := tx.QueryRow(ctx, `SELECT attempts FROM scheduled_jobs WHERE id = $1 FOR UPDATE`, id).Scan(&attempts)
		if errors.Is(err, pgx.ErrNoRows) {
			return jobs.ErrJobNotFound
		}
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres jobs: read attempts", err)
		}
		if attempts >= maxAttempts {
			_, err = tx.Exec(ctx, `UPDATE scheduled_jobs SET status = $1, claimed_at = NULL WHERE id = $2`,
				int(jobs.StatusFailed), id)
		} else {
			newFireAt := now.Add(time.Duration(attempts) * backoff)
			_, err = tx.Exec(ctx, `UPDATE scheduled_jobs SET status = $1, fire_at = $2, claimed_at = NULL WHERE id = $3`,
				int(jobs.StatusPending), newFireAt, id)
		}
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "postgres jobs: mark failed", err)
		}
		return nil
	})
}

// ResetToPending transitions a Running row back to Pending without
// bumping Attempts. Idempotent for missing or non-Running rows. The
// UPDATE filters on status=Running so a concurrent MarkDone /
// MarkFailed cannot be clobbered.
func (s *JobsStore) ResetToPending(ctx context.Context, id string, fireAt time.Time) error {
	_, err := s.q.Exec(ctx,
		`UPDATE scheduled_jobs SET status = $1, fire_at = $2, claimed_at = NULL
		 WHERE id = $3 AND status = $4`,
		int(jobs.StatusPending), fireAt, id, int(jobs.StatusRunning))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "postgres jobs: reset to pending", err)
	}
	return nil
}

// RecoverStale re-queues Running rows whose claimed_at is NULL or
// before olderThan. The partial index on (claimed_at) where
// status=running keeps this scan cheap.
func (s *JobsStore) RecoverStale(ctx context.Context, olderThan time.Time) (int, error) {
	tag, err := s.q.Exec(ctx,
		`UPDATE scheduled_jobs SET status = $1, claimed_at = NULL
		 WHERE status = $2 AND (claimed_at IS NULL OR claimed_at < $3)`,
		int(jobs.StatusPending), int(jobs.StatusRunning), olderThan)
	if err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "postgres jobs: recover stale", err)
	}
	return int(tag.RowsAffected()), nil
}

// Get returns the job by ID.
func (s *JobsStore) Get(ctx context.Context, id string) (*jobs.Job, error) {
	const stmt = `
		SELECT id, job_type, fire_at, payload, status, attempts, created_at
		FROM scheduled_jobs
		WHERE id = $1`
	j := &jobs.Job{}
	var status int
	err := s.q.QueryRow(ctx, stmt, id).Scan(
		&j.ID, &j.Type, &j.FireAt, &j.Payload, &status, &j.Attempts, &j.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, jobs.ErrJobNotFound
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "postgres jobs: get", err)
	}
	j.Status = jobs.Status(status)
	return j, nil
}

func newJobID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
