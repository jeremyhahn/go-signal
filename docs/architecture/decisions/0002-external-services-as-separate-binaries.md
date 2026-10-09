# ADR-0002: External Signal services as separate binaries

> **Status: REFERENCE** · Last verified: 2026-10-09
> Decision record, corrected to the as-built service boundaries.

- **Status**: accepted
- **Date**: 2026-04-22
- **Author**: go-signal team

## Context

The Java Signal-Server's topology is not monolithic. The chat server is one service; registration, secure value recovery, contact discovery, storage and key transparency are separate services. Clients address several of them directly, with their own hostnames and auth flows, and the enclave-attested ones scale independently of the chat server.

## Decision

Each external Signal service is its own Go binary under `cmd/`:

```
cmd/signald/                 chat / messaging server
cmd/registration-service/    verification sessions
cmd/svr2/                    secure value recovery
cmd/cdsi/                    contact discovery
cmd/storage-service/         encrypted manifest storage
cmd/key-transparency/        key-transparency queries
```

Each has a Dockerfile in `deploy/` and a `make build-*` target. Shared code (config loading, cache, proto files, inter-service auth in `pkg/extservice/common`) lives in shared `pkg/` packages.

signald does not require the other binaries. Each integration is optional: with `verification.remoteAddr`, `storageService.remoteUrl`, `keyTransparency.remoteAddr` or `svr2.remoteUrl` unset, signald runs the registration engine and key-transparency manager in process and serves the storage endpoints itself.

The wire protocols differ per service:

| Service | Protocol |
|---|---|
| `registration-service`, `key-transparency` | gRPC from signald |
| `svr2`, `cdsi` | Noise NKhfs WebSocket from clients; HMAC-authenticated admin HTTP (svr2) and gRPC to signald's `DirectoryService` (cdsi) |
| `storage-service` | JSON over HTTPS with HMAC Basic auth |

TLS and mTLS between services are optional, configured through `pkg/extservice/common.TLSConfig`.

## Alternatives considered

- **Monolith** — simplest to build. Rejected: enclave-attested services run on different hardware and scale independently; the client protocol expects separate endpoints; operators lose the option to mix in external infrastructure.
- **Embedded now, extract later** — extraction rarely happens cleanly. Rejected; the in-process engines sit behind the same interfaces as the remote clients.
- **Client-only proxy to Signal.org infrastructure** — rejected; the project is an independent implementation.

## Consequences

- More moving parts per environment. `make dev` starts only signald; `deploy/docker-compose.yml` starts every service.
- Shared code must stay reusable; binary-specific logic belongs in that binary's `cmd/` or a binary-specific `pkg/` package.
- Service boundaries allow independent deployment and scaling.

## References

- [../topology.md](../topology.md)
