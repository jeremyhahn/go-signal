# ADR-0001: Pluggable storage with go-qrdb as the primary backend

- **Status**: accepted
- **Date**: 2026-04-22
- **Author**: go-signal team

## Context

The Java Signal-Server uses DynamoDB exclusively for persistent storage and Redis for caching. A Go port faces three realistic options for production storage:

1. Match Java 1:1 with DynamoDB — schema parity, but locks deployments to AWS.
2. Use Postgres — well-understood operationally, but requires translating DynamoDB access patterns to SQL.
3. Use an embedded or self-hosted KV store — self-contained, but diverges from Java's storage model.

go-signal's dependency tree already includes `github.com/jeremyhahn/go-qrdb`, a production-grade KV database with MVCC, secondary indexes, FTS, leases, RBAC, and certificate-based auth. It is maintained by the same organization and is built for the same deployment profile as this project.

We also want to support teams that deploy into AWS (DynamoDB) or prefer relational stores (Postgres). A single mandated backend would exclude reasonable deployment targets.

## Decision

Storage is pluggable through the existing `pkg/store.KVClient` interface. Three production backends are supported:

- **go-qrdb** — the primary, default production backend. Self-contained, no cloud dependency.
- **DynamoDB** — a first-class alternate with schema parity to Java Signal-Server, so operators can migrate state between the two implementations.
- **Postgres** — a third option via `pgx`, using JSONB for opaque attribute blobs and native columns for indexed fields.

The in-memory backend in `pkg/storage/memory/` stays for tests and `make dev`.

Selection happens at startup via `storage.backend` in YAML config.

## Alternatives considered

- **DynamoDB only** — simplest to build, but forces AWS. Rejected.
- **go-quicraft as primary** — Raft consensus KV; excellent for distributed state but overkill for single-region deployments and adds operational complexity. Used for specific subsystems (key-transparency append-only log, multi-instance coordination) but not as the default domain store.
- **Postgres only** — forces SQL translation effort for every domain; abandons the benefits of KV operations already modeled in the codebase.

## Consequences

- Per-domain stores (`AccountStore`, `MessageStore`, etc.) are written against `KVClient` once, then backend-specific optimizations (GSIs, composite indexes) are layered on top where they help.
- Every schema change must be applied to all three backends. The `storage/schema-*.md` docs track this.
- Integration tests must run against every backend. New `test/integration/storage/` suite runs the same contract tests against qrdb, DynamoDB (local), and Postgres.
- Operators picking DynamoDB get a trivial Java-to-Go migration path via schema parity. Operators picking go-qrdb or Postgres accept a more involved migration but gain operational flexibility.

## References

- Gap analysis plan: `/home/jhahn/.claude/plans/fluttering-kindling-flask.md`, Phase 1.1.
- Java schemas: `/mnt/vm-host-1/Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/`.
- go-qrdb source: `/mnt/vm-host-1/go-qrdb/pkg/kvstore/`.
