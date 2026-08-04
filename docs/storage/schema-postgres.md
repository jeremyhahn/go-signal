# Postgres storage schema

Postgres is one of three production backends supported by go-signal, alongside go-qrdb (default) and DynamoDB. The Postgres schema follows a hybrid design philosophy: columns commonly used in WHERE clauses or joins are promoted to the top level for indexing; opaque server blobs (encoded Account structs, group state, message envelopes) live in JSONB columns. This approach avoids the impedance mismatch of translating key-value domain operations to pure relational form while keeping hot queries efficient.

All schema creation is handled by the embedded migrator in `pkg/storage/postgres/migrate.go`. Migrations are sorted by version number, applied inside a Postgres advisory lock to serialize concurrent schema changes, and tracked in a `schema_migrations` bookkeeping table.

## Schema Design Principles

**JSONB is authoritative, columns are projections.** The `data` JSONB column in tables like `accounts` and `groups` holds the complete serialized struct. Promoted columns like `aci`, `version`, `e164` are copied from the struct on every write and stay in sync via application logic, not triggers. This keeps write transactions simple: parse once, extract promoted fields, serialize once. A database-level schema change never invalidates client code.

**Foreign-key CASCADE on the strictly account-bound tables.** The four pre-key tables and `profiles` reference `accounts(aci) ON DELETE CASCADE` — deleting the parent account removes their rows in one statement, no app code required. Other tables that hold an `account_uuid` column (`provisioning_sessions`, the username tables, `fido2_credentials`, `fido2_sessions`, `storage_manifests`, `storage_items`, `spam_reports`, `messages`, `verification_sessions`) deliberately omit the FK. Reasons vary: verification sessions exist *before* the account row during registration; spam reports outlive the reporter for moderation review; messages are self-expiring via the TTL sweeper. `DeleteForAccount` for those domains runs an explicit `DELETE FROM <table> WHERE account_uuid = $1` from the relevant store.

**TTL replacement: expires_at + periodic sweeper.** Postgres has no native TTL mechanism like DynamoDB or Redis. Tables with time-bound data (provisioning sessions, verification sessions, username reservations, messages) carry an `expires_at TIMESTAMPTZ` column with a partial index (`WHERE expires_at IS NOT NULL` for messages). Background worker processes run sweeper tasks that periodically `DELETE FROM table WHERE expires_at < NOW()`. This is scheduled lazily to keep schema uncluttered; Phase 1.4 workers define the cadence per table.

**Conditional write: ON CONFLICT, UNIQUE constraints, and advisory locks.** DynamoDB's conditional expressions (`ConditionExpression`, `LeadingKeys`) are replaced by:
- `UNIQUE` constraints for natural uniqueness (e.164 phone numbers, username hashes, credential IDs).
- `ON CONFLICT` clauses for idempotent upserts (e.g., pre-key replacement).
- Partial unique indexes (e.g., `profiles_latest_idx`) to enforce cardinality constraints like "at most one latest profile per account."
- Advisory locks (`pg_advisory_lock`) when coordinating across multiple statements that the database can't express as a single atomic operation (e.g., username reservation selecting a candidate, then inserting it with expiry).

---

## Migrations

Migrations are SQL files stored in `pkg/storage/postgres/migrations/` embedded at compile time via `//go:embed`. Files follow the naming convention `NNNN_name.up.sql` and `NNNN_name.down.sql`, where `NNNN` is a zero-padded version number. The migrator:

1. Acquires a Postgres advisory lock (`pg_advisory_lock(0x607551147A1A1B1C)`) to serialize concurrent migrations from multiple running instances.
2. Creates the `schema_migrations` table if it doesn't exist.
3. Reads the current maximum version from `schema_migrations`.
4. Executes each new migration in a transaction, inserting a row into `schema_migrations` on success.
5. Releases the advisory lock on completion.

Only versions strictly greater than the current maximum are applied; re-running a migration on the same database is safe.

See `pkg/storage/postgres/migrate.go` for the full implementation.

---

## Accounts

**Purpose:** Stores account records, one per ACI, with phone number, PNI, optional username hash, and full device list.

**Schema:**
```sql
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
```

**Indexes:** None at table level; `aci`, `pni`, `e164`, `username_hash`, and `username_link_handle` are all unique constraints or primary key, which Postgres indexes automatically.

**Promoted columns:**
- `aci`: Account identity UUID (primary key).
- `pni`: Phone Number Identity UUID (required, unique).
- `e164`: Phone number in E.164 format (required, unique). Used by `GetByNumber`.
- `username_hash`: Blake2b hash of the username, if claimed (nullable, unique). Used by username lookup.
- `username_link_handle`: The username handle if a link is active (nullable, unique).
- `version`: Optimistic lock counter for all updates.

**JSONB column:** `data` holds the complete serialized `accounts.Account` struct, including the nested `Devices` slice, `IdentityKey`, `PhoneNumberIdentityKey`, `UnidentifiedAccessKey`, and any other mutable fields.

**Lifecycle:** Accounts are created at registration and deleted explicitly on account removal. No automatic TTL.

**Conditional writes:** `Create` enforces uniqueness on `aci`, `pni`, `e164`, `username_hash`, and `username_link_handle` via Postgres UNIQUE constraints. On conflict, `AccountAlreadyExistsError` is returned with the conflicting identifier. `Update` uses optimistic locking: the submitted `version` must equal the stored version plus one, enforced by a `WHERE version = ?` clause.

**Java equivalent:** `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/Accounts.java` — direct mapping with identical column names and semantics.

**Implementation:** `pkg/storage/postgres/accounts.go` — `AccountStore` interface satisfied by `postgres.AccountStore`.

---

## Prekeys — EC and KEM

**Purpose:** Stores one-time and signed pre-keys for each account/device pair. Four families: EC one-time, KEM one-time, EC signed, KEM last-resort.

**Schema:**
```sql
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
```

**Indexes:** None; primary keys are automatically indexed.

**Lifecycle:** Created on device provisioning, replaced entirely by `StoreECPreKeys` and `StoreKEMPreKeys` (which first delete all existing keys for the device, then insert the new batch). One-time keys are consumed by `TakeEC` and `TakeKEM` in ascending key-ID order. Deleted when the device is removed.

**Conditional writes:** `TakeEC` and `TakeKEM` use a single atomic statement:
```sql
DELETE FROM prekeys_ec_onetime
WHERE account_uuid = $1 AND device_id = $2 AND key_id = (
    SELECT MIN(key_id) FROM prekeys_ec_onetime
    WHERE account_uuid = $1 AND device_id = $2
)
RETURNING public_key;
```
This eliminates the race condition present in KV backends where listing keys, picking the lowest, and deleting it requires three roundtrips. Postgres row locks serialize concurrent Takes on the same device naturally.

`StoreECPreKeys` and `StoreKEMPreKeys` use `pgx.Batch` to delete all old keys and insert the new batch in a single network roundtrip while running in a transaction.

**Java equivalent:** `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/Keys.java` — same table structure; the `keyId` field is mapped directly.

**Implementation:** `pkg/storage/postgres/keys.go` — `PreKeyStore` interface satisfied by `postgres.PreKeyStore`.

---

## Provisioning Sessions

**Purpose:** Temporary sessions created during device provisioning, keyed by a random verification code.

**Schema:**
```sql
CREATE TABLE provisioning_sessions (
    code         TEXT         PRIMARY KEY,
    account_uuid UUID         NOT NULL,
    expires_at   TIMESTAMPTZ  NOT NULL
);

CREATE INDEX provisioning_sessions_expires_idx
    ON provisioning_sessions (expires_at);
```

**Indexes:** `provisioning_sessions_expires_idx` for TTL sweep queries.

**Lifecycle:** Created when a secondary device begins provisioning. The session expires after a configured timeout (typically 10 minutes). The background sweeper periodically deletes rows where `expires_at < NOW()`.

**Conditional writes:** Natural primary key on `code` prevents duplicate sessions; on collision, a conflict error is returned.

**Java equivalent:** `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/ProvisioningCode.java` and the `ProvisioningCodeStore` — the `code` and `expiration` fields map directly.

**Implementation:** `pkg/storage/postgres/provisioning.go` — `ProvisioningStore` interface satisfied by `postgres.ProvisioningStore`.

---

## Usernames — Confirmed, Reserved, and Links

**Purpose:** Three tables implementing the two-phase username claim flow: reserve a hash for 5 minutes, then confirm it atomically.

**Schema:**
```sql
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
```

**Indexes:**
- `usernames_reserved_expires_idx` for TTL sweep of expired reservations.

**Promoted columns:**
- `usernames_confirmed`: `username_hash` (primary), `account_uuid` (unique). Lookup by hash returns ACI; reverse lookup by ACI returns hash.
- `usernames_reserved`: `account_uuid` (primary), `username_hash` (unique). Per-account reservation; only one account may reserve at a time.
- `username_links`: `handle` (primary), `account_uuid` (unique), `encrypted_username` (blob). Lookup by handle returns the encrypted username (which the client must decrypt).

**Lifecycle:**
- `ReserveHash` selects the first candidate hash from a list that is neither confirmed nor actively reserved (not expired) by another account. It stores the reservation under the account's UUID with a 5-minute expiry and a random token. If the same account reserves again, `ON CONFLICT (account_uuid) DO UPDATE` replaces the prior reservation.
- `ConfirmHash` validates the supplied token, then promotes the reservation to a confirmed entry: `DELETE FROM usernames_reserved WHERE account_uuid = ? AND token = ?; INSERT INTO usernames_confirmed...`.
- `DeleteHash` removes both the confirmed hash and any link for the account.
- `SetLink` stores the handle-to-link mapping; `GetLink` retrieves it by handle.

**Conditional writes:**
- `ReserveHash` runs inside a transaction that manually sweeps expired reservations at the start, then checks confirmed + reserved hashes in the candidate list. The advisory lock in `pkg/storage/postgres/usernames.go` coordinates this across multiple transactions.
- `UNIQUE` constraint on `username_hash` in `usernames_reserved` prevents two accounts from reserving the same hash concurrently; conflicts are mapped to `UsernameHashConflictError`.
- `UNIQUE` constraint on `account_uuid` in `usernames_confirmed` ensures only one hash per account.

**Java equivalent:**
- `usernames_confirmed` / `usernames_reserved`: `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/Usernames.java` — exact structure.
- `username_links`: `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/UsernameLinks.java` — same fields.

**Implementation:** `pkg/storage/postgres/usernames.go` — `UsernameStore` interface satisfied by `postgres.UsernameStore`. Uses `c.WithTx` for multi-statement atomicity.

---

## Groups

**Purpose:** Stores Signal group metadata, versioned by revision number.

**Schema:**
```sql
CREATE TABLE groups (
    id          TEXT         PRIMARY KEY,
    revision    BIGINT       NOT NULL DEFAULT 0,
    data        JSONB        NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
```

**Indexes:** None; `id` is the primary key.

**Promoted columns:**
- `id`: Group identifier (primary key).
- `revision`: Monotonically increasing version for optimistic concurrency control.

**JSONB column:** `data` holds the complete serialized `groups.Group` struct, including members, admins, avatar blob reference, and other mutable group state.

**Lifecycle:** Created when a user creates a group. Updated when group state changes (member added/removed, avatar updated, etc.). Deleted when the group is dissolved.

**Conditional writes:** `Update` enforces optimistic locking: the submitted `revision` must equal the stored revision plus one, via `WHERE revision = ?` in the update clause.

**Java equivalent:** `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/Groups.java` — matches the Java schema exactly.

**Implementation:** `pkg/storage/postgres/groups.go` — `GroupStore` interface satisfied by `postgres.GroupStore`.

---

## Messages

**Purpose:** Per-(account, device) message queue. Uses a global BIGSERIAL sequence to assign each message a strictly ordered ID, which serves as a cursor for clients.

**Schema:**
```sql
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
```

**Indexes:**
- `messages_queue_idx` for per-device queue retrieval in insertion order.
- `messages_expires_idx` (partial) for TTL-driven deletion; the partial filter avoids indexing rows with `NULL` expiry.

**Promoted columns:**
- `seq`: Global message counter (primary key). Assigned by Postgres on insert; returned to the caller and stored in `Envelope.ID` so clients have an opaque, stable cursor.
- `account_uuid`, `device_id`: Destination account and device.
- `server_guid`: Unique per-message identifier (e.g., UUID generated by the sender or server). Used for delete-by-GUID operations.
- `expires_at`: When the message should be purged (nullable). Currently always `NULL` because Signal mobile clients do not yet transmit per-message TTL in this API. Kept as a nullable column to enable per-row expiry in the future without schema changes.

**JSONB column:** `envelope` holds the complete serialized `messages.Envelope` struct.

**Lifecycle:** Messages are inserted into the per-device queue on arrival. Clients fetch messages for a device via `GetMessagesForDevice(uuid, device)`, which returns them in `seq` order. Messages can be deleted by `server_guid` (via index scan) or all messages for a device (via index scan). The TTL sweeper periodically deletes rows where `expires_at < NOW()`.

**Conditional writes:** `server_guid` is unique across the entire table, preventing duplicate message IDs. If a message arrives with a duplicate GUID, the database rejects it with a unique-constraint violation.

**Java equivalent:** `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/Messages.java` — same table and queue structure; the `seq` is the Postgres `BIGSERIAL` equivalent of Java's atomic counter.

**Implementation:** `pkg/storage/postgres/messages.go` — `MessageStore` interface satisfied by `postgres.MessageStore`.

---

## Profiles

**Purpose:** Versioned per-account profiles. Each account may have multiple profile versions; exactly one is marked as the latest.

**Schema:**
```sql
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
```

**Indexes:**
- `profiles_latest_idx` (partial unique) enforces at most one latest profile per account. A partial unique index only applies where the condition is true, so there can be at most one row per `account_uuid` with `is_latest = TRUE`.

**Promoted columns:**
- `account_uuid`, `version`: Composite primary key. Lookup by account UUID and version string.
- `is_latest`: Boolean flag indicating whether this version is the current one.

**JSONB column:** `data` holds the complete serialized `profiles.Profile` struct, including encrypted name, about text, avatar reference, and commitment.

**Lifecycle:** `Set(profile)` atomically demotes all existing latest rows for the account (setting `is_latest = FALSE`), then upserts the supplied version with `is_latest = TRUE`. This is run inside a transaction to guarantee the partial unique index is never violated.

**Conditional writes:** The partial unique index is the enforcement mechanism; no explicit `ON CONFLICT` is needed. The transaction ensures the index is not violated.

**Java equivalent:** `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/Profiles.java` — the qrdb Java implementation uses a separate mirror key `profile:{uuid}:_latest` to track latest; the Postgres schema achieves the same with a partial unique index.

**Implementation:** `pkg/storage/postgres/profiles.go` — `ProfileStore` interface satisfied by `postgres.ProfileStore`. Uses `c.WithTx` for atomic promotion of latest.

---

## Verification Sessions

**Purpose:** Temporary sessions for phone number or email verification during registration.

**Schema:**
```sql
CREATE TABLE verification_sessions (
    id          TEXT         PRIMARY KEY,
    data        JSONB        NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX verification_sessions_expires_idx
    ON verification_sessions (expires_at);
```

**Indexes:** `verification_sessions_expires_idx` for TTL sweep.

**Promoted columns:**
- `id`: Session identifier (primary key).
- `expires_at`: When the session expires.

**JSONB column:** `data` holds the complete serialized `verification.VerificationSession` struct. Note: the `Code` field is tagged `json:"-"` in the struct and is never written to the JSONB column. Verification codes are ephemeral secrets generated server-side and never persisted.

**Lifecycle:** Created at the start of verification. Expires after a configured timeout (typically 10 minutes). The background sweeper removes expired rows.

**Conditional writes:** Primary key on `id` prevents duplicate sessions.

**Java equivalent:** `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/VerificationSessionStore.java` — similar structure.

**Implementation:** `pkg/storage/postgres/verification.go` — `VerificationSessionStore` interface satisfied by `postgres.VerificationSessionStore`.

---

## FIDO2 Credentials and Sessions (build tag: `fido2`)

**Purpose:** WebAuthn (FIDO2) registration and ceremony state.

**Schema:**
```sql
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
```

**Indexes:**
- `fido2_credentials_account_idx` for `GetCredentialsByAccount` queries.
- `fido2_sessions_expires_idx` for TTL sweep.

**Promoted columns:**
- `fido2_credentials`: `credential_id` (primary), `account_uuid` (indexed). Used to list all credentials for an account.
- `fido2_sessions`: `id` (primary), `account_uuid` (indexed, nullable), `expires_at` (indexed). Registration and assertion ceremony sessions.

**JSONB columns:**
- `fido2_credentials.data`: Serialized `fido2.FIDO2Credential` struct, including the attested credential data.
- `fido2_sessions.data`: Serialized `fido2.FIDO2Session` struct, including challenge and state.

**Lifecycle:** Credentials are registered once and persist until deleted by the user. Sessions are ephemeral and expire after the ceremony timeout (typically 5–10 minutes). The sweeper removes expired sessions.

**Conditional writes:** `credential_id` is unique; duplicate registrations conflict with `CredentialExistsError`.

**Java equivalent:** `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/Credentials.java` and `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/PushChallengeSessions.java` — similar structure.

**Implementation:** `pkg/storage/postgres/fido2.go` — `FIDO2AccountsStore` interface satisfied by `postgres.FIDO2AccountsStore` (build-tagged `fido2`).

---

## Secure Storage (Encrypted user backups)

**Purpose:** Encrypted user-controlled backup data: manifest and items.

**Schema:**
```sql
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
```

**Indexes:** None; primary keys are automatically indexed.

**Promoted columns:**
- `storage_manifests`: `account_uuid` (primary). Manifest version is monotonically checked on `PutManifest` — the new version must be strictly greater than the stored version.
- `storage_items`: `account_uuid`, `item_key` (composite primary). Items are keyed per-account.

**BYTEA columns:** Both `value` fields hold opaque encrypted data and are never unpacked by the server.

**Lifecycle:** The manifest is updated whenever the user uploads new backup state. Items are inserted, updated, or deleted per user action. No automatic TTL.

**Conditional writes:** `PutManifest` enforces monotonic versioning via application-level checks: the submitted version must be strictly greater than the stored version, enforced in the service layer.

**Java equivalent:** `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/StorageServiceStore.java` — same structure and semantics.

**Implementation:** `pkg/storage/postgres/securestorage.go` — `SecureStorageStore` interface satisfied by `postgres.SecureStorageStore`.

---

## Spam Reports

**Purpose:** Records of user-reported spam, keyed by report ID.

**Schema:**
```sql
CREATE TABLE spam_reports (
    id             UUID         PRIMARY KEY,
    reporter_uuid  UUID         NOT NULL,
    source_uuid    UUID,
    message_guid   UUID,
    reported_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX spam_reports_reporter_idx
    ON spam_reports (reporter_uuid);
```

**Indexes:** `spam_reports_reporter_idx` for queries like `GetByReporter`.

**Promoted columns:**
- `id`: Report identifier (primary key).
- `reporter_uuid`: Account UUID of the reporter.
- `source_uuid`: Account UUID of the reported sender (nullable).
- `message_guid`: GUID of the reported message (nullable).

**Lifecycle:** Reports are created when users submit spam complaints and are never deleted (kept for audit and analysis). No TTL.

**Conditional writes:** None; the primary key on `id` is naturally unique.

**Java equivalent:** `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/ReportMessageDynamoDb.java` — similar structure.

**Implementation:** `pkg/storage/postgres/reports.go` — `SpamReportStore` interface satisfied by `postgres.SpamReportStore`.

---

## Relationships and Cascading Deletes

Two groups:

**Cascade.** The four pre-key tables and `profiles` declare `account_uuid REFERENCES accounts(aci) ON DELETE CASCADE`. `DELETE FROM accounts WHERE aci = $1` cleans them up in one statement.

**Explicit per-store DELETE.** `provisioning_sessions`, `usernames_confirmed`, `usernames_reserved`, `username_links`, `fido2_credentials`, `fido2_sessions`, `storage_manifests`, `storage_items`, `spam_reports`, `messages`, and `verification_sessions` hold an `account_uuid` column without a foreign key. Some entries exist before the account row (verification during registration), some intentionally outlive the account (`spam_reports` for moderation review), some have their own lifecycle (`messages` purged by the TTL sweeper). The corresponding `DeleteForAccount` / `DeleteAll` methods on each store run an explicit `DELETE FROM <table> WHERE account_uuid = $1`.

---

## Implementation Patterns in pkg/storage/postgres

All domain-specific store implementations follow a consistent pattern:

1. **Compile-time interface check.** Each file has a `var _ SomeDomainStore = (*SomeStore)(nil)` line to catch interface drift at build time.

2. **Querier abstraction.** Stores accept a `Querier` interface (satisfied by both `*pgxpool.Pool` and `pgx.Tx`) so they work standalone or participate in outer transactions.

3. **JSON serialization for JSONB.** Domain structs are serialized to JSONB via `json.Marshal` on write and deserialized on read. Schema updates never require database migrations when new fields are added to the struct (they simply become part of the JSONB blob); removing fields requires a careful deprecation process.

4. **Promoted column sync.** Columns like `version`, `account_uuid`, and `expires_at` are extracted from the struct and stored separately. The application code maintains this sync; the database doesn't.

5. **Transaction support.** Methods that require atomicity across multiple statements use `c.WithTx` (a helper that takes either a pool or a pre-existing transaction) to open a transaction if needed, or reuse an existing one if already inside one.

6. **Typed errors.** Domain-specific errors (e.g., `AccountAlreadyExistsError`, `UsernameHashConflictError`) are returned to the caller, never generic strings. Error mapping from Postgres constraint violations uses helpers like `IsUniqueViolation` in `pkg/storage/postgres/client.go`.
