//go:build desktop

// Package jobs provides a persistent async job queue backed by the
// JobEntity DAO. Jobs survive application restarts and are processed
// with configurable retry logic.
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// JobFunc processes a job. Return nil on success, error to retry.
type JobFunc func(ctx context.Context, data json.RawMessage) error

// Queue is a persistent job queue backed by the JobEntity DAO.
// Job types are registered via map-based dispatch.
type Queue struct {
	dao       dao.GenericDAO[*entities.JobEntity]
	handlers  map[string]JobFunc
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	pollInterval time.Duration
}

// NewQueue creates a job queue backed by the given DAO.
func NewQueue(jobDAO dao.GenericDAO[*entities.JobEntity]) *Queue {
	return &Queue{
		dao:          jobDAO,
		handlers:     make(map[string]JobFunc),
		pollInterval: 2 * time.Second,
	}
}

// Register adds a job handler for the given queue type.
func (q *Queue) Register(queueType string, handler JobFunc) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.handlers[queueType] = handler
}

// Enqueue creates a new pending job.
func (q *Queue) Enqueue(ctx context.Context, queueType string, data interface{}) error {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("jobs: marshal data: %w", err)
	}

	job := &entities.JobEntity{
		QueueType:   queueType,
		Data:        string(dataBytes),
		Status:      entities.JobStatusPending,
		Attempts:    0,
		MaxAttempts: 3,
		CreatedAt:   time.Now().UnixMilli(),
		NextRunAt:   time.Now().UnixMilli(),
	}
	return q.dao.Save(ctx, job)
}

// Start begins the job processing loop. Runs until Stop is called.
func (q *Queue) Start(ctx context.Context) {
	q.mu.Lock()
	q.ctx, q.cancel = context.WithCancel(ctx)
	q.mu.Unlock()

	go q.processLoop()
}

// Stop gracefully shuts down the job queue.
func (q *Queue) Stop() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.cancel != nil {
		q.cancel()
	}
}

// processLoop polls for pending jobs and processes them.
func (q *Queue) processLoop() {
	ticker := time.NewTicker(q.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-q.ctx.Done():
			return
		case <-ticker.C:
			q.processPending()
		}
	}
}

// processPending finds and executes all pending jobs that are due.
func (q *Queue) processPending() {
	ctx, cancel := context.WithTimeout(q.ctx, 30*time.Second)
	defer cancel()

	now := time.Now().UnixMilli()

	// Query pending jobs. The compound index (QueueType, Status, NextRunAt)
	// will be used by the planner for efficient querying.
	jobs, err := q.dao.Find(ctx).
		Where("Status = ?", entities.JobStatusPending).
		Execute()
	if err != nil {
		return
	}

	for _, job := range jobs {
		if job.NextRunAt > now {
			continue // not yet due
		}

		q.mu.RLock()
		handler, ok := q.handlers[job.QueueType]
		q.mu.RUnlock()

		if !ok {
			continue // no handler registered
		}

		// Mark as running.
		job.Status = entities.JobStatusRunning
		job.Attempts++
		_ = q.dao.Save(ctx, job)

		// Execute.
		execErr := handler(ctx, json.RawMessage(job.Data))

		if execErr != nil {
			if job.Attempts >= job.MaxAttempts {
				job.Status = entities.JobStatusFailed
				job.LastError = execErr.Error()
			} else {
				job.Status = entities.JobStatusPending
				job.LastError = execErr.Error()
				// Exponential backoff: 2^attempts seconds.
				delay := time.Duration(1<<uint(job.Attempts)) * time.Second
				job.NextRunAt = time.Now().Add(delay).UnixMilli()
			}
		} else {
			job.Status = entities.JobStatusCompleted
		}

		_ = q.dao.Save(ctx, job)
	}
}
