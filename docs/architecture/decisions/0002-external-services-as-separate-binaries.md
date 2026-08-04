# ADR-0002: External Signal services as separate binaries

- **Status**: accepted
- **Date**: 2026-04-22
- **Author**: go-signal team

## Context

Java Signal-Server's topology is not monolithic. The chat server (`textsecuregcm`) is one service, and several other capabilities live in separate codebases and run as independent services:

- `registration-service` — phone/voice verification, invoking Twilio Verify.
- `SVR2` / `SVR3` — Secure Value Recovery, SGX-attested.
- `CDSI` — Contact Discovery Service, SGX-attested privacy-preserving lookup.
- `storage-service` — user-manifest encrypted storage.
- `key-transparency` — append-only log with VRF + Merkle proofs.

The client protocol expects these services to be independently addressable (different hostnames, different attestation chains, different auth flows). The SGX-attested services in particular run on specialized hardware and scale independently of the chat server.

A Go port can take two approaches:

1. **Monolith** — embed all services inside `signald`. Simplest deployment, single binary.
2. **Separate binaries** — one Go binary per Java service. Matches Java topology.

## Decision

Each external Signal service is built as its own Go binary under `cmd/`:

```
cmd/signald/                 ← chat / messaging server
cmd/registration-service/    ← verification session management
cmd/svr2/                    ← secure value recovery v4
cmd/cdsi/                    ← contact discovery
cmd/storage-service/         ← user-manifest store
cmd/key-transparency/        ← append-only log
```

Each has its own config, Dockerfile, Kubernetes manifest, and `make` targets. They communicate over gRPC with mTLS.

Shared code (config loading, KV store, cache, workers, proto files, inter-service auth) lives in shared `pkg/` packages reused by every binary.

Stub handlers in today's `signald` (`handlers_svr.go`, `handlers_keytransparency.go`, etc.) are replaced by gRPC clients to the respective services as each comes online in Phase 4.

## Alternatives considered

- **Monolith** — Simplest to build, easier local development. Rejected because:
  - SGX-attested services need to run on different hardware than the chat server; embedding forces the whole server onto SGX hardware.
  - Independent scaling is impossible.
  - Client protocol assumes service-specific attestation chains and separate endpoints.
  - Operators who want to use external Signal infrastructure for some services (e.g., production-grade SVR2) and self-host others lose that option.
- **Embedded now, extract later** — Tempting, but extraction-later rarely happens cleanly. Building the boundary up-front forces the right abstractions early.
- **Client-only** — Thin frontend to real Signal.org infrastructure. Rejected because the project's goal is a true independent implementation, not a proxy.

## Consequences

- More moving parts in every environment. `make dev` starts only `signald`; `docker-compose up` starts the full six-binary topology.
- mTLS between services must be set up and rotated.
- Shared code must stay genuinely reusable — any one-binary-specific logic belongs in that binary's `cmd/` or a binary-specific `pkg/` package, not in the shared tree.
- Clear service boundaries enable independent deployment, scaling, and security review.
- Direct correspondence to Java Signal-Server topology simplifies operator migration.

## References

- Plan: Phase 4 of `/home/jhahn/.claude/plans/fluttering-kindling-flask.md`.
- Java sources: `/mnt/vm-host-1/Signal-Server/service/`, plus the sibling `registration-service`, `SVR2-Signal`, `ContactDiscoveryService-*`, `KeyTransparencyService` repositories.
