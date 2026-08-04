package qrdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/jobs"
)

const jobKeyPrefix = "scheduledjobs:"

// JobsStore is a qrdb-backed jobs.Store. Keys: `scheduledjobs:<id>`
// → JSON-encoded jobRow.
type JobsStore struct {
	kv KVStore
}

// Compile-time interface satisfaction check.
var _ jobs.Store = (*JobsStore)(nil)

// NewJobsStore returns a store backed by kv.
func NewJobsStore(kv KVStore) *JobsStore {
	return &JobsStore{kv: kv}
}

type jobRow struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	FireAt    time.Time `json:"fireAt"`
	Payload   []byte    `json:"payload,omitempty"`
	Status    int       `json:"status"`
	Attempts  int       `json:"attempts"`
	CreatedAt time.Time `json:"createdAt"`
	// ClaimedAt is the wall-clock UTC at which the row was last
	// transitioned to Running. RecoverStale uses it to detect rows
	// whose worker died mid-execution. Zero when the row is not
	// (and has never been) Running — also acts as the "needs
	// recovery" signal on rows persisted before this field landed.
	ClaimedAt time.Time `json:"claimedAt,omitempty"`
}

func toRow(j *jobs.Job) jobRow {
	return jobRow{
		ID:        j.ID,
		Type:      j.Type,
		FireAt:    j.FireAt,
		Payload:   j.Payload,
		Status:    int(j.Status),
		Attempts:  j.Attempts,
		CreatedAt: j.CreatedAt,
	}
}

func fromRow(r jobRow) *jobs.Job {
	return &jobs.Job{
		ID:        r.ID,
		Type:      r.Type,
		FireAt:    r.FireAt,
		Payload:   r.Payload,
		Status:    jobs.Status(r.Status),
		Attempts:  r.Attempts,
		CreatedAt: r.CreatedAt,
	}
}

// Enqueue persists job. Assigns ID + CreatedAt when empty.
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
	if job.CreatedAt.IsZero() {
		job.CreatedAt = time.Now().UTC()
	}
	if job.Status == 0 {
		job.Status = jobs.StatusPending
	}
	data, err := json.Marshal(toRow(job))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: encode", err)
	}
	return s.kv.Put(ctx, jobKeyPrefix+job.ID, data)
}

// errStopJobsScan is a sentinel returned from a Scan callback to stop
// iteration cleanly. ClaimDue uses it to bail once `limit` matches
// have been collected so the underlying KV store doesn't keep
// streaming rows that would be ignored.
var errStopJobsScan = errors.New("qrdb jobs: stop scan")

// ClaimDue scans all rows, picks ones with FireAt<=now & Pending,
// transitions them to Running, and returns up to limit. When types
// is non-empty, only rows whose Type is in the set are eligible.
func (s *JobsStore) ClaimDue(ctx context.Context, now time.Time, limit int, types ...string) ([]*jobs.Job, error) {
	allow := buildTypeFilter(types)
	var out []*jobs.Job
	var doomed []*jobs.Job // collected first; mutation happens after scan to avoid concurrent map iteration semantics
	err := s.kv.Scan(ctx, jobKeyPrefix, func(_ string, value []byte) error {
		if len(out)+len(doomed) >= limit {
			return errStopJobsScan
		}
		var r jobRow
		if err := json.Unmarshal(value, &r); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: decode", err)
		}
		if jobs.Status(r.Status) != jobs.StatusPending {
			return nil
		}
		if r.FireAt.After(now) {
			return nil
		}
		if allow != nil {
			if _, ok := allow[r.Type]; !ok {
				return nil
			}
		}
		doomed = append(doomed, fromRow(r))
		return nil
	})
	if err != nil && !errors.Is(err, errStopJobsScan) {
		return nil, err
	}
	for _, j := range doomed {
		j.Status = jobs.StatusRunning
		j.Attempts++
		row := toRow(j)
		row.ClaimedAt = now
		data, err := json.Marshal(row)
		if err != nil {
			return out, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: re-encode", err)
		}
		if err := s.kv.Put(ctx, jobKeyPrefix+j.ID, data); err != nil {
			return out, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: claim put", err)
		}
		out = append(out, j)
	}
	return out, nil
}

// MarkDone deletes the job by ID.
func (s *JobsStore) MarkDone(ctx context.Context, id string) error {
	return s.kv.Delete(ctx, jobKeyPrefix+id)
}

// MarkFailed re-queues with backoff or marks Failed when exhausted.
func (s *JobsStore) MarkFailed(ctx context.Context, id string, now time.Time, backoff time.Duration, maxAttempts int) error {
	data, err := s.kv.Get(ctx, jobKeyPrefix+id)
	if err != nil {
		return err
	}
	if data == nil {
		return jobs.ErrJobNotFound
	}
	var r jobRow
	if err := json.Unmarshal(data, &r); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: decode", err)
	}
	if r.Attempts >= maxAttempts {
		r.Status = int(jobs.StatusFailed)
	} else {
		r.Status = int(jobs.StatusPending)
		r.FireAt = now.Add(time.Duration(r.Attempts) * backoff)
	}
	r.ClaimedAt = time.Time{}
	out, err := json.Marshal(r)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: encode", err)
	}
	return s.kv.Put(ctx, jobKeyPrefix+id, out)
}

// ResetToPending transitions a Running row back to Pending without
// bumping Attempts. Idempotent for missing or non-Running rows.
func (s *JobsStore) ResetToPending(ctx context.Context, id string, fireAt time.Time) error {
	data, err := s.kv.Get(ctx, jobKeyPrefix+id)
	if err != nil {
		return err
	}
	if data == nil {
		return nil
	}
	var r jobRow
	if err := json.Unmarshal(data, &r); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: decode", err)
	}
	if jobs.Status(r.Status) != jobs.StatusRunning {
		return nil
	}
	r.Status = int(jobs.StatusPending)
	r.FireAt = fireAt
	r.ClaimedAt = time.Time{}
	out, err := json.Marshal(r)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: encode", err)
	}
	return s.kv.Put(ctx, jobKeyPrefix+id, out)
}

// RecoverStale re-queues Running rows whose ClaimedAt is before
// olderThan. A Running row with zero ClaimedAt is treated as stale
// — that state can only occur on rows persisted before the field
// existed or after an unclean shutdown.
func (s *JobsStore) RecoverStale(ctx context.Context, olderThan time.Time) (int, error) {
	var stale []jobRow
	err := s.kv.Scan(ctx, jobKeyPrefix, func(_ string, value []byte) error {
		var r jobRow
		if err := json.Unmarshal(value, &r); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: decode", err)
		}
		if jobs.Status(r.Status) != jobs.StatusRunning {
			return nil
		}
		if !r.ClaimedAt.IsZero() && !r.ClaimedAt.Before(olderThan) {
			return nil
		}
		stale = append(stale, r)
		return nil
	})
	if err != nil {
		return 0, err
	}
	recovered := 0
	for _, r := range stale {
		// Re-fetch immediately before the overwrite so a
		// concurrent ClaimDue that re-claimed the same row in
		// the window between Scan and now isn't clobbered. The
		// authoritative signal is the row's ClaimedAt — if it
		// shifted since our scan, leave the row alone and let
		// the new claimant own it.
		live, err := s.kv.Get(ctx, jobKeyPrefix+r.ID)
		if err != nil {
			return recovered, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: recover refetch", err)
		}
		if live == nil {
			// Row gone (MarkDone won the race) — nothing to recover.
			continue
		}
		var current jobRow
		if err := json.Unmarshal(live, &current); err != nil {
			return recovered, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: recover decode", err)
		}
		if jobs.Status(current.Status) != jobs.StatusRunning {
			continue
		}
		if !current.ClaimedAt.Equal(r.ClaimedAt) {
			// A concurrent ClaimDue re-claimed; the new
			// worker owns the row now.
			continue
		}
		current.Status = int(jobs.StatusPending)
		current.ClaimedAt = time.Time{}
		data, err := json.Marshal(current)
		if err != nil {
			return recovered, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: encode", err)
		}
		if err := s.kv.Put(ctx, jobKeyPrefix+current.ID, data); err != nil {
			return recovered, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: recover put", err)
		}
		recovered++
	}
	return recovered, nil
}

// Get returns the job by ID.
func (s *JobsStore) Get(ctx context.Context, id string) (*jobs.Job, error) {
	data, err := s.kv.Get(ctx, jobKeyPrefix+id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, jobs.ErrJobNotFound
	}
	var r jobRow
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb jobs: decode", err)
	}
	return fromRow(r), nil
}

func newJobID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// buildTypeFilter returns a set keyed by type. Nil result means
// "no filter — accept every type".
func buildTypeFilter(types []string) map[string]struct{} {
	if len(types) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(types))
	for _, t := range types {
		out[t] = struct{}{}
	}
	return out
}
