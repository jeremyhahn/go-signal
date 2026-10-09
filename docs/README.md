# go-signal documentation

> **Status: REFERENCE** · Last verified: 2026-10-09
> Index of the documentation tree and how it is maintained.

This directory holds the documentation for go-signal. Every document opens with a status banner and a `Last verified:` date, following the handbook documentation convention.

## Reading order

1. [architecture/overview.md](architecture/overview.md): the layered architecture and how requests flow end to end.
2. [architecture/topology.md](architecture/topology.md): the six-binary deployment model and how the services talk to each other.
3. [architecture/package-map.md](architecture/package-map.md): where each capability lives in the source tree.
4. [architecture/decisions/](architecture/decisions/): ADRs for the non-obvious design decisions.
5. [api/](api/): REST, gRPC and WebSocket interfaces.
6. [protocol/](protocol/): protocol-level details (PNI).
7. [storage/](storage/): the `KVClient` contract, store interfaces per backend, qrdb and Postgres schemas, Redis keys.
8. [workers/](workers/): background workers, their schedules and leader election.
9. [auth/](auth/): authentication and FIDO2.
10. [verification/](verification/): phone-number verification and its transports.
11. [messaging/](messaging/): message envelope and delivery.
12. [configuration/](configuration/): YAML config reference and secret URI resolution.
13. [deployment/](deployment/): building, Docker, testing and production readiness.
14. [services/](services/): index of the service binaries.
15. [migrations/](migrations/): pointer to the schema-migration docs.
16. [contributing/](contributing/): development setup.

## How the tree is organized

Each top-level subdirectory owns a concern. A change that spans concerns gets a doc in each relevant subdirectory plus an ADR in `architecture/decisions/` that ties them together.

## Generated documentation

No documentation is generated from source today. The `make docs` targets (`docs-rest`, `docs-grpc`, `docs-config`, `docs-storage`, `docs-workers`) are placeholders that print a message, so every file here is hand-maintained.

## Editing conventions

- Every architectural change adds or updates one ADR.
- Every new package, endpoint, worker, config key, or Redis/DB key gets a doc entry in the same change.
- Update `../CHANGELOG.md` with every user-visible change.
- Update `../CLAUDE.md` when the agent-facing architecture surface changes.
