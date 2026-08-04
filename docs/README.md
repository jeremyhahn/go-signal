# go-signal documentation

This directory holds the living documentation for go-signal. Every architectural change ships with the docs that explain it. A new engineer should be able to onboard from these files without reading the source.

## Reading order

1. [architecture/overview.md](architecture/overview.md) — three-layer architecture, how requests flow end-to-end.
2. [architecture/topology.md](architecture/topology.md) — the six-binary deployment model and how services talk to each other.
3. [architecture/package-map.md](architecture/package-map.md) — where each capability lives in the source tree.
4. [architecture/decisions/](architecture/decisions/) — ADRs for every non-obvious design decision.
5. [api/](api/) — REST, gRPC, and WebSocket interface documentation.
6. [protocol/](protocol/) — Signal-protocol-level details: PNI, PQ keys, ZK credentials, message delivery.
7. [storage/](storage/) — KV layout per backend, Redis key conventions.
8. [workers/](workers/) — background workers and their schedules.
9. [auth/](auth/) — authentication and FIDO2.
10. [verification/](verification/) — phone/email verification transports.
11. [messaging/](messaging/) — message envelope, sealed sender, multi-recipient delivery.
12. [configuration/](configuration/) — YAML config reference and secret URI resolution.
13. [deployment/](deployment/) — building, Docker, runbooks, observability.
14. [services/](services/) — one document per external service binary (signald, registration, svr2, cdsi, storage-service, key-transparency).
15. [migrations/](migrations/) — operator guides for migrating between versions or from Java Signal-Server.
16. [contributing/](contributing/) — development setup, testing, project conventions.

## How the tree is organized

Each top-level subdirectory owns a concern. A change that spans concerns gets a doc in each relevant subdirectory plus an ADR in `architecture/decisions/` that ties them together.

## Generated documentation

Some docs are generated from source, not hand-written. `make docs` regenerates them; CI enforces no drift. Generated files:

- `api/rest.md` — from route registrations in `pkg/api/rest/`.
- `api/grpc.md` — from `.proto` files via `protoc-gen-doc`.
- `configuration/reference.md` — from tagged Go structs in `pkg/config/`.
- `storage/schema-*.md` — from table/keyspace registry code.

Hand-written Mermaid sequence diagrams under `architecture/sequence-diagrams/` are source-committed as `.mmd` files so they can be re-rendered.

## Editing conventions

- Prose goes through the `humanizer` skill before landing.
- Every architectural change adds or updates one ADR.
- Every new package, endpoint, worker, config key, or Redis/DB key gets a doc entry in the same PR.
- Update `../CHANGELOG.md` with every user-visible change.
- Update `../CLAUDE.md` when the agent-facing architecture surface changes.
