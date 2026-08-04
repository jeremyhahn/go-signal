# Changelog

All notable changes to go-signal are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Embedded storage-service (contact/settings sync), enabled by default in monolithic mode (`storageService.remoteUrl` empty). Implements the real protobuf storage protocol — `GET /v1/storage/manifest[/version/{v}]`, `PUT /v1/storage` (`WriteOperation`), `PUT /v1/storage/read` (`ReadOperation` → `StorageItems`) — backed by `ManifestStore` with monotonic versioning and `409`-on-conflict. Validated wire-compatible with libsignal-service-java. (`pkg/securestorage`, `pkg/api/rest/handlers_storage_manifest.go`, `pkg/securestorage/proto/storage.proto`)
- Real profile-key credential issuance at `GET /v1/profile/{id}/{version}/{credentialRequest}`, using zkgroup deserialization from go-libsignal. Fails closed (`400`) on proof/commitment mismatch. (`pkg/api/rest/handlers_profile_credentials.go`, `pkg/certificates`)
- Real AWS SigV4 S3 POST-policy signing for avatar uploads from configured CDN credentials; fails closed (`503`) when the CDN is unconfigured. (`pkg/auth/s3_post_policy.go`, `handlers_profile.go`)
- `store.KVClient.DeleteIfPresent` — atomic check-and-delete primitive. (`pkg/store/kv.go`)
- `storageService` configuration section (`StorageServiceConfig`). (`pkg/config/config.go`)

### Security

- Per-device authentication. Both the REST `authMiddleware` and the gRPC `AuthenticatedUnary` interceptor now verify the credential against the *addressed* device (`uuid.deviceId`), not always the primary device, and expose the authenticated device ID via `deviceIDFromContext` / `interceptors.DeviceIDFromContext`. Auth tokens are compared as salted HKDF-SHA256 digests (`auth.SaltedTokenHash`) in constant time, with timing-equalisation on every failure path. (`pkg/api/rest/middleware.go`, `pkg/api/grpc/interceptors/auth.go`)
- Change-number (`PUT /v2/accounts/number`) now requires proof of ownership of the new number (a verified session or matching recovery password, mutually exclusive), restricts the call to the primary device, rotates the PNI, and persists per-device PNI pre-keys after validating them up front. (`handlers_accounts_v2.go`, `accounts/manager.go` `ChangeNumber`)
- One-time pre-key consumption is now atomic via `KVClient.DeleteIfPresent`, so a pre-key is never handed to two concurrent sessions. Last-resort PQ keys live in a separate namespace and are read without consumption. (`pkg/keys/store_kv.go`)
- `KVAccountStore.Create`/`Update` perform compensating rollback of the by-number/by-pni secondary indexes on partial-write failure. (`pkg/accounts/store_kv.go`)
- Profile field ciphertext lengths enforced at `PUT /v1/profile` (name 81/285, about 156/282/540, aboutEmoji 60, paymentAddress 582, commitment 97 bytes). (`handlers_profile.go`)
- group-send token HMAC now uses length-prefixed framing to remove field-boundary ambiguity. (`pkg/auth/group_send_token.go`)

### Changed

- REST `Server` fields are now `pkg/service` interfaces rather than concrete managers, per the service-layer convention. (`pkg/api/rest/server.go`)
- `go.mod` now includes `replace` directives pointing local module dependencies (`go-libsignal`, `go-qrdb`, `go-qrdb/sdk/go`, `go-quicraft`) at their `/mnt/vm-host-1/...` paths.

### Docs scaffold (Phase 0)

- Documentation tree scaffold under `docs/` expanded with new subdirectories for architecture decisions, sequence diagrams, services, protocol, workers, storage, migrations, and contributing guides.
- Initial Architecture Decision Records:
  - ADR-0001: Pluggable storage with go-qrdb as the primary backend.
  - ADR-0002: External Signal services as separate binaries.
  - ADR-0003: Skip payments in the port.
  - ADR-0004: Pluggable verification transport abstraction.
- `docs/README.md` index with reading order for the documentation tree.
- `docs/architecture/topology.md` describing the six-binary target deployment.
- `docs/contributing/development-setup.md` covering sshfs, symlinks, and module resolution.
- `CHANGELOG.md` (this file).

### Fixed

- Restored `go.sum` via `go mod tidy` after initial repository setup left it missing.
- Applied `gofmt` to 29 files across `cmd/signal/cmd/`, `pkg/api/rest/`, `pkg/daostore/`, `pkg/desktop/`, `sdk/go/`, and `test/integration/api/` that were out of compliance with the project's gofmt-clean convention.

### Build

- Added `make docs`, `make docs-check`, and per-generator `docs-*` targets as placeholders for the documentation generation pipeline. Each real generator is enabled in the phase that introduces its source data (gRPC proto generator in Phase 1, REST route registry dumper in Phase 2, etc.).

## Phase 1.1 — qrdb storage backend

### Added

- `pkg/storage/qrdb/` — new backend package implementing every production domain store on top of `go-qrdb`. Types implemented:
  - `AccountStore` — CRUD with optimistic locking on `Account.Version` and a mirror index for `GetByNumber`.
  - `ProvisioningStore` — device provisioning sessions keyed by code.
  - `GroupStore` — CRUD with optimistic locking on `Group.Revision`.
  - `ProfileStore` — versioned profiles with `_latest` mirror for `GetLatest`.
  - `VerificationSessionStore` — verification sessions with expiry sweep via `DeleteExpired`.
  - `ReportStore` — spam reports scoped per reporter UUID.
  - `SecureStorageStore` — per-account manifest + item storage with monotonic version enforcement.
  - `UsernameStore` — hash reservation/confirmation with tokens, confirmed-hash mirror, and username links.
  - `MessageStore` — per-device message queues with GUID-indexed delete.
  - `PreKeyStore` — EC one-time, KEM one-time, KEM last-resort, and signed pre-keys with per-device take locks.
  - `FIDO2AccountsStore` (build tag `fido2`) — WebAuthn credential and session storage.
- `FakeKVStore` — minimal in-memory `KVStore` for unit tests, committed under `pkg/storage/qrdb/testutil.go`.
- Test coverage: 79% (target 90%, remaining gaps are error-propagation paths that can be closed with the `faultyKV` pattern established in `errors_test.go`; see task 1.1 coverage push).
- Documentation note: every store follows a consistent key-layout convention documented in each file's leading comment.

### Design decisions

- Each backend implements domain store interfaces directly rather than layering on a generic KV adapter. This matches the existing `pkg/storage/memory` convention and preserves the ability to use backend-specific optimizations (native indexes, batch writes) without forcing a common denominator.
- Secondary lookups use mirror keys (e.g., `account:by-number:{e164} → UUID`) rather than qrdb native secondary indexes, because mirror keys work uniformly across qrdb transports. Native index integration is a later optimization.
- JSON is the value-serialization format — portable and introspectable.
- Optimistic concurrency is enforced by read-compare-write on `Version` / `Revision` fields, matching the memory-backed stores.

### Deferred

- `attachments.Store` is intentionally not implemented in qrdb. Binary blob storage belongs in `pkg/storage/blob/` (Phase 3.5) against S3 / GCS / Azure / local filesystem.
- DynamoDB (`pkg/storage/dynamodb/`) and Postgres (`pkg/storage/postgres/`) backends deferred until a deployment requires them. The per-backend pattern established in qrdb is directly reusable.

## Phase 1.2 — Redis cache layer

### Added

- `pkg/cache/` — `Client` interface covering keyed values, counters, distributed locks, sorted sets, hashes, pub/sub, and Lua script execution.
- `pkg/cache/memory/` — in-process `Client` implementation for tests and single-node deployments. Coverage: 91.9%.
- `pkg/cache/redis/` — production `Client` backed by `github.com/redis/go-redis/v9`. Unit coverage covers construction + config propagation; full method coverage requires a live Redis server and is exercised via integration tests.
- New dependencies: `github.com/redis/go-redis/v9`, `github.com/dgryski/go-rendezvous`, `go.uber.org/atomic`.

## Phase 1.3 — gRPC scaffold

### Added

- `pkg/api/grpc/proto/` — every `.proto` from `Signal-Server/service/src/main/proto/` and `Signal-Server/websocket-resources/src/main/proto/` copied in verbatim. Only change: `option go_package` added to each file.
- `pkg/api/grpc/genproto/` — generated `.pb.go` + `_grpc.pb.go` for 19 proto files spanning 16 services. Regenerated with `make proto` (updated to handle the nested-output flattening).
- `pkg/api/grpc/interceptors/` — `AuthenticatedUnary` (port of the REST Basic-auth middleware) and `AnonymousUnary` (rejects any authenticated metadata). 100% test coverage.
- `pkg/api/grpc/services/` — Server-side stubs for every proto service, each embedding the generated `Unimplemented<Name>Server` so every RPC returns `codes.Unimplemented` cleanly.
- `pkg/api/grpc/server.go` — `Server` type that registers all 16 services against a single `grpc.Server`, with a routing interceptor that picks authenticated / anonymous / pass-through per method prefix. 91.5% test coverage.
- `make proto` target updated and idempotent (`cp -r` instead of `mv` so reruns don't fail on existing directories).
- New dependencies: `google.golang.org/grpc`, plus the `protoc-gen-go` + `protoc-gen-go-grpc` toolchain.

## Phase 1.4 — Background-worker framework

### Added

- `pkg/workers/` — scheduler supporting three execution shapes (cron via `robfig/cron/v3`, continuous loops with backoff, on-demand).
- `workers.CacheLeaser` — leader-election wrapper around `cache.Client.Lock` so one replica at a time runs each worker. Token-based release prevents the classic stale-lease double-unlock race.
- Worker implementations ported from Java Dropwizard commands (stubs wired; Run bodies land phase-by-phase):
  - Cleanup: `remove-expired-accounts`, `remove-expired-linked-devices`, `remove-expired-username-holds`, `remove-orphaned-pre-key-pages`.
  - Device activity: `notify-idle-devices`, `unlink-idle-primary`.
  - Continuous services: `message-persister`, `process-scheduled-jobs`, `scheduled-apn-sender`.
  - Administrative: `generate-certificate`, `generate-zk-params`, `check-dynamic-config`.
- `workers.RegisterDefaults` wires the full catalog onto a scheduler with one call.
- Package coverage: 95.1%.

## Phase 1.5 — Wire-up in signald

### Added

- `cmd/signald/start.go`: qrdb storage backend case, cache-client construction (Redis or memory), gRPC server startup alongside REST, worker scheduler startup.
- `service.SignalService` is now constructed in `start.go` and passed to the gRPC server; it becomes the central injection point as Phase 2 methods swap the `Unimplemented` embeds for real logic.
- Graceful shutdown order: WebSocket sessions → HTTP → gRPC → background goroutines → secret-material teardown.
- `pkg/config.StorageConfig.Backend` comment updated to include `"qrdb"`.

## Phase 1.6 — Phase 1 documentation

### Added

- `docs/storage/schema-qrdb.md` — full key layout for every qrdb domain store.
- `docs/storage/redis-keys.md` — Redis key-pattern catalog covering leader leases, rate limits, message queues, MRM hashes, pub/sub channels.
- `docs/workers/catalog.md` — one-table-per-category inventory of every registered worker.
- `docs/workers/scheduling.md` — scheduler model, leader-election semantics, shutdown order.
- `docs/api/grpc.md` — service catalog split by auth mode, interceptor chain documentation, client usage example.

## Phase 2.1.1 — PNI on the account model

### Added

- `Account.PNI` field storing the Phone Number Identity UUID, distinct from the ACI in `Account.UUID`.
- `AccountsManager.Create` auto-assigns a random PNI when none is supplied; callers that manage PNI externally (e.g. account-transfer flows) can set it explicitly and the manager preserves it.
- `AccountsManager.GetByPNI` and the corresponding `AccountStore.GetByPNI` on every backend (memory, qrdb, KV).
- PNI mirror secondary indexes on every backend, maintained across Create / Update (phone-number-change flow) / Delete.
- `docs/protocol/pni.md` documenting the ACI/PNI model and what's implemented vs. deferred to 2.1.2 and 2.1.3.

## Phase 2.1.2 — Identity-namespaced key storage

### Added

- `accounts.IdentityType` enum (`IdentityTypeACI` / `IdentityTypePNI`).
- `Account.IdentityUUID(IdentityType)` accessor.
- `KeysManager` gains `*ForIdentity` variants (`StoreKeysForIdentity`, `GetPreKeysForIdentity`, `GetPreKeyCountForIdentity`, `StoreSignedPreKeyForIdentity`, `StoreKEMPreKeysForIdentity`, `StoreKEMLastResortPreKeyForIdentity`) that resolve the correct UUID from an account + identity type before dispatching to the underlying `PreKeyStore`.
- `keys.ErrIdentityNotSet` sentinel for accounts missing the requested identity.
- Tests verifying ACI and PNI land in distinct key namespaces. Package coverage 90.5%.

## Phase 2.1.3 — Message routing scaffold

### Added

- `Envelope.DestinationIdentityType` and `IncomingMessage.DestinationIdentityType` discriminants (zero value treated as ACI for backwards compatibility).
- `messages.ResolveDestinationAccount` helper dispatches to `Get` (ACI) or `GetByPNI` (PNI) based on the identity type.
- `Envelope.StorageNamespace()` accessor documents the convention that the stores key messages under the raw UUID regardless of identity type.

## Phase 2.4.1 — Message persistence pipeline

### Added

- `messages.CacheQueue` — cache-backed staging buffer keyed by `(uuid, device)`. Sorted set `q:{uuid}:{device}` carries server-GUID order, side hash `qm:{uuid}:{device}` holds the JSON envelopes. TTLs are re-armed on every Enqueue, Remove is idempotent, orphan members are swept during Drain.
- `messages.MessagePersister` — drains the cache queue into a durable `MessageStore` device-by-device. Per-device errors are logged and the loop continues; per-tick batch size is configurable via `PersisterConfig.MaxPerDevice` (default 100).
- `messages.PersisterDeviceLister` interface decouples queue-presence discovery from the persister; production wiring will back it with a Redis SCAN, tests use a fixed list.
- `MessagePersisterWorker` (in `pkg/workers/jobs.go`) now holds a real `*messages.MessagePersister` and delegates `Run` to it. When the persister is nil the worker is a no-op so default registration still works in environments that haven't wired the pipeline.
- `pkg/messages` test coverage at 94.4%.

## Project history

go-signal is a Go port of the Java Signal-Server reference implementation. The work is tracked in phases in the top-level plan (`/home/jhahn/.claude/plans/fluttering-kindling-flask.md`):

- **Phase 0**: Prerequisites — module resolution, docs scaffold, changelog setup *(current)*.
- **Phase 1**: Foundation — pluggable storage, Redis cache, gRPC scaffold, background worker framework.
- **Phase 2**: Core protocol — PNI, real ZK credentials, PQ keys, message delivery, backups.
- **Phase 3**: Integrations — APNs/FCM, verification transports, CAPTCHA, TURN, attachments, device check.
- **Phase 4**: External services — registration-service, svr2, cdsi, storage-service, key-transparency as separate binaries.
- **Phase 5**: Production readiness — observability, health, multi-instance coordination, hardening, performance.

Each phase contributes an entry to this changelog under its corresponding `[x.y.z]` release.
