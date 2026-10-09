# ADR-0005: Postgres storage schema design

> **Status: REFERENCE** · Last verified: 2026-10-09
> Decision record for the Postgres backend, corrected to the as-built code.

- **Status**: accepted
- **Date**: 2026-05-06
- **Author**: go-signal team

## Context

[ADR-0001](0001-pluggable-storage.md) established pluggable storage backends, including Postgres. The Postgres backend requires a concrete schema design. Unlike DynamoDB (which uses untyped key-value attributes) or go-qrdb (which uses JSON documents keyed by domain-specific prefixes), Postgres is a relational system with native support for typed columns, indexes, constraints, and transactions.

The challenge is translating Signal's domain operations — which were modeled for KV or semi-structured backends — into a relational schema without losing the advantages of both worlds: the schema simplicity of JSON-in-DB and the query efficiency of normalized columns.

## Decision

The Postgres schema follows a hybrid design:

1. **Domain interfaces as the seam, not `KVClient`.** Every store (AccountStore, MessageStore, PreKeyStore, etc.) is implemented directly against Postgres tables, not layered on top of a generic KV abstraction. This allows schema-specific optimizations (e.g., atomic pre-key consumption via `DELETE...RETURNING`) that would be invisible or impossible in a KV layer. The service layer is the abstraction boundary, not the storage layer.

2. **Hybrid columns + JSONB.** Columns commonly used in WHERE clauses, joins, or uniqueness constraints are promoted to the top level (e.g., `account_uuid`, `e164`, `version`, `expires_at`). Opaque server blobs — complete Account structs, Group state, Message envelopes — live in JSONB. This avoids the impedance mismatch of trying to express every domain field as a relational column while keeping hot queries (by ACI, by phone number, by expiry) fast.

3. **Selective FK CASCADE from accounts(aci).** The four pre-key tables and `profiles` declare `account_uuid REFERENCES accounts(aci) ON DELETE CASCADE` — those rows have no meaningful life outside their parent account, so a single `DELETE FROM accounts` cleans them up. Other tables that hold an `account_uuid` (verification sessions, provisioning sessions, the username tables, FIDO2, secure storage, spam reports, messages) intentionally omit the FK. Each has its own lifecycle reason: verification sessions exist *before* the account row during registration, spam reports outlive the reporter for moderation review, messages self-expire via the TTL sweeper, and others simply have a clean per-domain delete that's easier to reason about than implicit cascades. The cost is one extra DELETE per store in `DeleteForAccount`.

4. **Hand-rolled migrator.** Rather than integrate `golang-migrate` or another third-party migration tool, migrations are embedded SQL files (`pkg/storage/postgres/migrations/NNNN_name.up.sql`) paired with a thin Go wrapper that uses Postgres advisory locks to serialize concurrent migrations. This keeps the import surface small and gives operators direct visibility into schema changes (readable .sql files checked into version control).

5. **expires_at + background sweeper as TTL replacement.** Postgres has no native TTL like DynamoDB or Redis. Tables with time-bound data carry an `expires_at TIMESTAMPTZ` column with an optional partial index. Background jobs in `pkg/workers/jobs.go` (for example the remove-expired-messages job) periodically `DELETE FROM table WHERE expires_at < NOW()`. This is lazier than native TTL but requires zero cloud dependency and integrates cleanly with go-signal's worker framework.

6. **ON CONFLICT + UNIQUE + advisory locks for conditional writes.** DynamoDB's conditional expressions are replaced by:
   - UNIQUE constraints and primary keys for natural uniqueness.
   - ON CONFLICT clauses for idempotent upserts (e.g., pre-key replacement).
   - Partial unique indexes for cardinality constraints (e.g., "exactly one latest profile per account").
   - Transactions (`Client.WithTx`) for operations that coordinate across multiple statements (e.g., "select a username hash that no other account has reserved"). The only advisory lock is the migrator's.

7. **JSONB authoritative, columns are projections.** The JSONB column (e.g., `data` in accounts, groups, messages) holds the complete serialized struct. Promoted columns are copied from the struct on every write and stay in sync via application code, not triggers. This keeps schema migrations simple: adding a new field to the struct doesn't require a database alter; the field becomes part of the JSONB blob on next write.

## Alternatives considered

- **All-JSONB, minimal columns.** Store everything as JSONB with no promoted columns. This would simplify schema changes and keep Postgres "dumb." Rejected: inefficient queries. Every "get account by phone number" would require a full table scan with JSONB extraction; every TTL sweep would scan all rows and deserialize JSONB to check `expires_at`.

- **All-columns, normalized relational.** Explode every domain field into its own column. This maximizes query efficiency and keeps data strictly typed. Rejected: maintenance burden. Every schema change to a domain struct would require a migration; new optional fields would need careful NULL handling; nested structures (Device list in Account, Member list in Group) would require junction tables or unsupported JSON arrays.

- **Layered on top of KVClient.** Implement PreKeyStore, MessageStore, etc. as wrappers around a generic KV backend that translates domain queries to KV operations. Rejected: loses the benefits of relational operations. Atomic pre-key consumption would require list-get-delete in three steps with inherent races; conditional writes would rely on pessimistic locking rather than native constraints.

- **golang-migrate or sql-migrate.** Use an off-the-shelf migration library. Rejected: unnecessary external dependency. The hand-rolled migrator (`pkg/storage/postgres/migrate.go`) handles advisory locks, bookkeeping, and version tracking. go-signal's slim import surface is a deliberate architectural choice.

## Consequences

**Gained:**
- Schema specificity. Postgres schemas are directly readable and directly modifiable (no opaque KV prefix conventions).
- Query efficiency. Hot paths like "get account by phone" and TTL sweeps use native indexes and are O(log n), not O(n).
- Atomic operations. Pre-key consumption, username reservation, profile promotion — all use single-statement atomicity or explicit transactions.
- Zero-copy deployments. Operators can inspect and back up the schema directly; no need to understand KV prefix conventions or secondary index strategies.
- Migration clarity. Every schema change is a readable .sql file in version control; no implicit migrations hidden in code.

**Costs:**
- Multiple schema versions to maintain. Changes to the Postgres schema may also need to be applied to the qrdb stores. `docs/storage/schema-*.md` files track this.
- Schema coupling. The Postgres schema defines what domain fields are indexed. Adding a new commonly-queried field may require a database index; removing an indexed field requires coordination between application code and the schema.
- No automatic TTL. Background workers must be deployed and scheduled to manage `expires_at` cleanup. This is operationally simpler than cloud-provider TTL but requires monitoring and tuning.

## References

- [ADR-0001](0001-pluggable-storage.md): storage pluggability.
- [../../storage/schema-postgres.md](../../storage/schema-postgres.md): table-by-table reference.
- Implementation: `pkg/storage/postgres/` (store implementations, embedded migrations).
- Contract tests: `test/integration/storage/`.
