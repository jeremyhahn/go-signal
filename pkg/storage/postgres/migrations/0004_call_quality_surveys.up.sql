-- ============================================================================
-- CALL QUALITY SURVEYS
--
-- Mirrors Java Signal-Server's call-quality survey persistence. Java only
-- writes call-quality surveys to Postgres (every other table is DynamoDB);
-- we follow that policy so the analytics pipeline reading the Postgres
-- table sees the same shape across implementations.
--
-- response_id is the client-supplied opaque identifier (we never link it
-- back to an account; the endpoint is intentionally unauthenticated).
-- It's stored verbatim so duplicate submissions land as a UNIQUE-violation
-- the publisher can ignore.
-- ============================================================================

CREATE TABLE call_quality_surveys (
    response_id              TEXT         PRIMARY KEY,
    submission_timestamp     TIMESTAMPTZ  NOT NULL,
    user_satisfied           BOOLEAN      NOT NULL,
    start_timestamp          TIMESTAMPTZ  NOT NULL,
    end_timestamp            TIMESTAMPTZ  NOT NULL,
    call_type                TEXT         NOT NULL,
    success                  BOOLEAN      NOT NULL,
    call_end_reason          TEXT         NOT NULL DEFAULT '',
    quality_issues           TEXT[]       NOT NULL DEFAULT '{}',
    additional_notes         TEXT         NOT NULL DEFAULT '',
    debug_log_url            TEXT         NOT NULL DEFAULT '',
    client_platform          TEXT         NOT NULL DEFAULT '',
    client_version           TEXT         NOT NULL DEFAULT '',
    remote_addr              TEXT         NOT NULL DEFAULT '',
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX call_quality_surveys_created_idx
    ON call_quality_surveys (created_at);
