-- ============================================================================
-- SCHEDULED JOBS — claimed_at column for stale-claim recovery
--
-- Adds a column that records when a row was last transitioned to
-- Running. The jobs.RecoverStale path re-queues rows whose
-- claimed_at is older than the operator's max-handler-runtime
-- threshold so that crashed-mid-execution jobs always get retried.
--
-- Rows persisted before this migration carry NULL and are treated
-- as stale (the only reason an existing Running row has NULL
-- claimed_at is the migration just ran on a process that was
-- mid-run).
-- ============================================================================

ALTER TABLE scheduled_jobs ADD COLUMN claimed_at TIMESTAMPTZ;

-- Recovery filter: status=running AND claimed_at < threshold.
-- Partial index keeps lookup cheap as Failed rows accumulate.
CREATE INDEX scheduled_jobs_running_claimedat_idx
    ON scheduled_jobs (claimed_at)
    WHERE status = 2;
