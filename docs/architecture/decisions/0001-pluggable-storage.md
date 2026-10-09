# ADR-0001: Pluggable storage

> **Status: REFERENCE** · Last verified: 2026-10-09
> Decision record, corrected to the as-built backends.

- **Status**: accepted
- **Date**: 2026-04-22
- **Author**: go-signal team

## Context

The Java Signal-Server uses DynamoDB for persistent storage and Redis for caching. A Go port can match that (locks deployments to AWS), use Postgres (requires translating access patterns to SQL), or use an embedded or self-hosted KV store such as `github.com/jeremyhahn/go-qrdb`. A single mandated backend would exclude reasonable deployment targets.

## Decision

Each domain package declares the store interface it needs, and `cmd/signald` selects the implementation from `storage.backend`. That interface is the seam between domain logic and storage.

| `storage.backend` | Implementation |
|---|---|
| `memory` (default) | `pkg/storage/memory`; tests and `make dev` |
| `file` | `store.FileKVClient` with the domain `store_kv.go` implementations |
| `postgres` | `pkg/storage/postgres`; see [ADR-0005](0005-postgres-storage-schema.md) |
| `qrdb` | `pkg/storage/qrdb` stores; startup wires an in-process fake KV store |

`pkg/store.KVClient` is the key-value interface used by the `file` backend and the `store_kv.go` implementations. The `postgres` backend does not use it.

DynamoDB is not implemented. An unknown or `dynamodb` value of `storage.backend` falls through to `memory`.

## Alternatives considered

- **DynamoDB only** — simplest to build, but forces AWS. Rejected.
- **go-quicraft as primary** — Raft consensus KV; overkill for single-region deployments. Rejected as the default domain store.
- **Postgres only** — forces SQL translation for every domain. Rejected as the sole backend.

## Consequences

- A schema change must be applied to each backend that stores the affected domain. [../../storage/schema-postgres.md](../../storage/schema-postgres.md) and [../../storage/schema-qrdb.md](../../storage/schema-qrdb.md) track the schemas.
- Contract tests for the backends are in `test/integration/storage/`.
- Production mode (`mode: production`) accepts only `postgres` and `file`.

## References

- [../overview.md](../overview.md#storage)
- [../../storage/overview.md](../../storage/overview.md)
