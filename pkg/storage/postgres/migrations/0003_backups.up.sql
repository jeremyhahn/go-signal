-- ============================================================================
-- BACKUPS
--
-- Mirrors Java Signal-Server's Backups DynamoDB table (BackupsDb / RemoteStorageManager).
-- Per-user metadata for the message-archive subsystem; one row per
-- backup-id (keyed by SHA-256-truncated-to-16-bytes of the un-hashed
-- BackupID — the canonical form Java BackupsDb persists as KEY_BACKUP_ID_HASH).
--
-- backup_dir / media_dir are short random base64url strings that prefix the
-- user's CDN content; rotating these is how DeleteEntireBackup orphans the
-- old prefix for asynchronous purge. The pending-deletion side-table records
-- in-progress prefix purges so the expiration worker can resume after a crash.
-- ============================================================================

CREATE TABLE backups (
    hashed_backup_id     BYTEA        PRIMARY KEY,
    public_key           BYTEA        NOT NULL,
    backup_level         INTEGER      NOT NULL,
    backup_dir           TEXT         NOT NULL,
    media_dir            TEXT         NOT NULL,
    last_refresh         TIMESTAMPTZ  NOT NULL,
    last_media_refresh   TIMESTAMPTZ  NOT NULL,
    bytes_used           BIGINT       NOT NULL DEFAULT 0,
    num_objects          BIGINT       NOT NULL DEFAULT 0,
    usage_recalc_at      TIMESTAMPTZ
);

-- Used by the RemoveExpiredBackups worker to find rows whose refresh
-- timestamp predates the configured grace period.
CREATE INDEX backups_last_refresh_idx
    ON backups (last_refresh);

CREATE INDEX backups_last_media_refresh_idx
    ON backups (last_media_refresh);

-- ============================================================================
-- BACKUPS_PENDING_DELETION
--
-- Side-table for in-progress CDN prefix purges. ScheduleBackupDeletion
-- rotates the user's directories, then queues the old prefix here for the
-- ExpireBackup worker to delete asynchronously. A row exists exactly when
-- a previous deletion has not completed; ExpireBackup removes the row
-- after the CDN prefix has been fully purged.
-- ============================================================================

CREATE TABLE backups_pending_deletion (
    hashed_backup_id   BYTEA        NOT NULL,
    prefix             TEXT         NOT NULL,
    last_refresh       TIMESTAMPTZ  NOT NULL,
    queued_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (hashed_backup_id, prefix)
);

-- ============================================================================
-- BACKUP_REDEEMED_RECEIPTS
--
-- Dedup table for paid-tier receipt redemptions. Mirrors Java's
-- RedeemedReceipts table; receipt serials are unique across the whole
-- system to prevent a single receipt extending more than one account's
-- voucher. Rows are kept until expires_at so a sweeper job can reclaim
-- space when receipts naturally expire.
-- ============================================================================

CREATE TABLE backup_redeemed_receipts (
    receipt_serial   BYTEA        PRIMARY KEY,
    expires_at       TIMESTAMPTZ  NOT NULL,
    receipt_level    BIGINT       NOT NULL,
    account_uuid     UUID         NOT NULL,
    redeemed_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX backup_redeemed_receipts_expires_idx
    ON backup_redeemed_receipts (expires_at);
