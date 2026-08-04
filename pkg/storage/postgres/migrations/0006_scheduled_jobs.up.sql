-- ============================================================================
-- SCHEDULED JOBS
--
-- Backing store for ProcessScheduledJobsServiceCommand-equivalent
-- deferred work. Each row represents one unit of work that fires at
-- `fire_at`. Workers atomically claim due rows (SELECT ... FOR UPDATE
-- SKIP LOCKED) so multiple instances can drain in parallel without
-- double-execution.
--
-- status values:
--   1 = pending (eligible for ClaimDue)
--   2 = running (claimed by a worker; not eligible)
--   3 = failed  (retry budget exhausted; left for operator
--                inspection)
-- ============================================================================

CREATE TABLE scheduled_jobs (
    id          TEXT        PRIMARY KEY,
    job_type    TEXT        NOT NULL,
    fire_at     TIMESTAMPTZ NOT NULL,
    payload     BYTEA       NOT NULL DEFAULT '\x'::bytea,
    status      INTEGER     NOT NULL,
    attempts    INTEGER     NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ClaimDue scans by (status=pending, fire_at <= now) — a partial
-- index on the pending subset is the cheapest way to keep it fast
-- as the dead/failed rows accumulate.
CREATE INDEX scheduled_jobs_pending_fireat_idx
    ON scheduled_jobs (fire_at)
    WHERE status = 1;
