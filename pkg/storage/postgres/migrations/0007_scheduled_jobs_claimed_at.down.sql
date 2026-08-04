DROP INDEX IF EXISTS scheduled_jobs_running_claimedat_idx;
ALTER TABLE scheduled_jobs DROP COLUMN IF EXISTS claimed_at;
