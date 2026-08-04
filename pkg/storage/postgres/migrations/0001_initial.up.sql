-- 0001_initial.up.sql
--
-- Initial Postgres schema for go-signal. Maps the domain repository
-- interfaces in pkg/service/* to native Postgres tables. Hybrid layout:
-- indexed/queried fields are promoted to columns; opaque server blobs
-- (Devices list, profile encrypted fields, group state, message envelope)
-- live in JSONB.
--
-- TTL replacement: every TTL-bearing table gets an expires_at TIMESTAMPTZ
-- column with an index, swept by a per-table worker (Phase 1.4).
-- Uniqueness/conditional-write replacement: ON CONFLICT + UNIQUE constraints
-- where the constraint is natural; advisory locks for the operations Java
-- uses DynamoDB Lock Client for.
--
-- Foreign keys cascade from accounts(aci) so DeleteForAccount is one DELETE.
--
-- Migrations are wrapped in a transaction by the runner; do not add
-- BEGIN/COMMIT here.

-- ============================================================================
-- ACCOUNTS
-- ============================================================================

CREATE TABLE accounts (
    aci                   UUID         PRIMARY KEY,
    pni                   UUID         NOT NULL UNIQUE,
    e164                  TEXT         NOT NULL UNIQUE,
    username_hash         BYTEA        UNIQUE,
    username_link_handle  TEXT         UNIQUE,
    version               BIGINT       NOT NULL DEFAULT 0,
    data                  JSONB        NOT NULL,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- PRE-KEYS
--
-- Four families:
--   prekeys_ec_onetime         — one-time EC pre-keys, consumed by Take.
--   prekeys_kem_onetime        — one-time KEM/Kyber pre-keys, consumed.
--   prekeys_ec_signed          — current signed EC pre-key per device (1).
--   prekeys_kem_lastresort     — current last-resort signed KEM pre-key (1).
-- ============================================================================

CREATE TABLE prekeys_ec_onetime (
    account_uuid  UUID    NOT NULL REFERENCES accounts(aci) ON DELETE CASCADE,
    device_id     BIGINT  NOT NULL,
    key_id        BIGINT  NOT NULL,
    public_key    BYTEA   NOT NULL,
    PRIMARY KEY (account_uuid, device_id, key_id)
);

CREATE TABLE prekeys_kem_onetime (
    account_uuid  UUID    NOT NULL REFERENCES accounts(aci) ON DELETE CASCADE,
    device_id     BIGINT  NOT NULL,
    key_id        BIGINT  NOT NULL,
    public_key    BYTEA   NOT NULL,
    signature     BYTEA   NOT NULL,
    PRIMARY KEY (account_uuid, device_id, key_id)
);

CREATE TABLE prekeys_ec_signed (
    account_uuid  UUID    NOT NULL REFERENCES accounts(aci) ON DELETE CASCADE,
    device_id     BIGINT  NOT NULL,
    key_id        BIGINT  NOT NULL,
    public_key    BYTEA   NOT NULL,
    signature     BYTEA   NOT NULL,
    PRIMARY KEY (account_uuid, device_id)
);

CREATE TABLE prekeys_kem_lastresort (
    account_uuid  UUID    NOT NULL REFERENCES accounts(aci) ON DELETE CASCADE,
    device_id     BIGINT  NOT NULL,
    key_id        BIGINT  NOT NULL,
    public_key    BYTEA   NOT NULL,
    signature     BYTEA   NOT NULL,
    PRIMARY KEY (account_uuid, device_id)
);

-- ============================================================================
-- PROVISIONING (device-link sessions)
-- ============================================================================

CREATE TABLE provisioning_sessions (
    code         TEXT         PRIMARY KEY,
    account_uuid UUID         NOT NULL,
    expires_at   TIMESTAMPTZ  NOT NULL
);

CREATE INDEX provisioning_sessions_expires_idx
    ON provisioning_sessions (expires_at);

-- ============================================================================
-- USERNAMES
--
-- Three tables matching the qrdb layout:
--   usernames_confirmed  — committed username hashes.
--   usernames_reserved   — pending hash reservations (5-min TTL).
--   username_links       — handle → encrypted-username mapping.
-- ============================================================================

CREATE TABLE usernames_confirmed (
    username_hash  BYTEA        PRIMARY KEY,
    account_uuid   UUID         NOT NULL UNIQUE,
    confirmed_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE usernames_reserved (
    account_uuid   UUID         PRIMARY KEY,
    username_hash  BYTEA        NOT NULL UNIQUE,
    token          TEXT         NOT NULL,
    expires_at     TIMESTAMPTZ  NOT NULL
);

CREATE INDEX usernames_reserved_expires_idx
    ON usernames_reserved (expires_at);

CREATE TABLE username_links (
    handle              TEXT   PRIMARY KEY,
    account_uuid        UUID   NOT NULL UNIQUE,
    encrypted_username  BYTEA  NOT NULL
);

-- ============================================================================
-- GROUPS
-- ============================================================================

CREATE TABLE groups (
    id          TEXT         PRIMARY KEY,
    revision    BIGINT       NOT NULL DEFAULT 0,
    data        JSONB        NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- MESSAGES
--
-- Per-(account, device) queue. seq is a global BIGSERIAL — strictly stronger
-- than the per-device monotonic contract, and gives callers a stable cursor.
-- server_guid is unique across the whole table for delete-by-guid.
-- expires_at populated on insert; sweeper purges past deadline.
-- ============================================================================

CREATE TABLE messages (
    seq           BIGSERIAL    PRIMARY KEY,
    account_uuid  UUID         NOT NULL,
    device_id     BIGINT       NOT NULL,
    server_guid   UUID         NOT NULL UNIQUE,
    envelope      JSONB        NOT NULL,
    inserted_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at    TIMESTAMPTZ
);

CREATE INDEX messages_queue_idx
    ON messages (account_uuid, device_id, seq);

CREATE INDEX messages_expires_idx
    ON messages (expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================================
-- PROFILES
--
-- Versioned per-account. is_latest flag (with partial unique index)
-- enforces exactly-zero-or-one "latest" row per account. The qrdb impl
-- uses a separate "_latest" mirror — same effect, native here.
-- ============================================================================

CREATE TABLE profiles (
    account_uuid  UUID         NOT NULL REFERENCES accounts(aci) ON DELETE CASCADE,
    version       TEXT         NOT NULL,
    data          JSONB        NOT NULL,
    is_latest     BOOLEAN      NOT NULL DEFAULT FALSE,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (account_uuid, version)
);

CREATE UNIQUE INDEX profiles_latest_idx
    ON profiles (account_uuid) WHERE is_latest = TRUE;

-- ============================================================================
-- VERIFICATION SESSIONS
-- ============================================================================

CREATE TABLE verification_sessions (
    id          TEXT         PRIMARY KEY,
    data        JSONB        NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX verification_sessions_expires_idx
    ON verification_sessions (expires_at);

-- ============================================================================
-- FIDO2 (WebAuthn)
-- ============================================================================

CREATE TABLE fido2_credentials (
    credential_id  TEXT         PRIMARY KEY,
    account_uuid   UUID         NOT NULL,
    data           JSONB        NOT NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX fido2_credentials_account_idx
    ON fido2_credentials (account_uuid);

CREATE TABLE fido2_sessions (
    id           TEXT         PRIMARY KEY,
    account_uuid UUID,
    data         JSONB        NOT NULL,
    expires_at   TIMESTAMPTZ  NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX fido2_sessions_expires_idx
    ON fido2_sessions (expires_at);

-- ============================================================================
-- SECURE STORAGE (user manifest + items)
-- ============================================================================

CREATE TABLE storage_manifests (
    account_uuid  UUID         PRIMARY KEY,
    version       BIGINT       NOT NULL,
    value         BYTEA        NOT NULL,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE storage_items (
    account_uuid  UUID         NOT NULL,
    item_key      BYTEA        NOT NULL,
    value         BYTEA        NOT NULL,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (account_uuid, item_key)
);

-- ============================================================================
-- SPAM REPORTS
-- ============================================================================

CREATE TABLE spam_reports (
    id             UUID         PRIMARY KEY,
    reporter_uuid  UUID         NOT NULL,
    source_uuid    UUID,
    message_guid   UUID,
    reported_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX spam_reports_reporter_idx
    ON spam_reports (reporter_uuid);
