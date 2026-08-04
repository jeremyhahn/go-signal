-- ============================================================================
-- REMOTE CONFIG
--
-- Persistent feature-flag store for signald's dynamic-configuration
-- manager. A single row per Config; UUIDs (the explicit allowlist) is
-- stored as a JSONB array of strings. Java parity: the same shape backs
-- the JDBI dao in Signal-Server.
--
-- One row per Name. Name is the natural primary key. The store is
-- mutated via the admin REST surface; the manager polls GetAll on a
-- refresh interval, so write volume is low and read volume is bounded
-- by the active config count (typically < 200).
-- ============================================================================

CREATE TABLE remote_config (
    name           TEXT        PRIMARY KEY,
    percentage     INTEGER     NOT NULL CHECK (percentage >= 0 AND percentage <= 100),
    uuids          JSONB       NOT NULL DEFAULT '[]'::jsonb,
    value          TEXT        NOT NULL DEFAULT '',
    default_value  TEXT        NOT NULL DEFAULT '',
    hash_key       TEXT        NOT NULL DEFAULT '',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
