# Changelog

All notable changes to go-signal are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Test TLS material is generated at test time, never committed. `make test-tls` (`test/tls/generate-certs.sh`) writes a short-lived ECDSA P-256 CA and server certificate under `test/tls/`, regenerating them when missing or within a day of expiry, and discards the CA key once the leaf is signed. `integration-test`, `integration-test-cli`, `integration-test-fido2` and `docker-build-dev` run it first, and the devcontainer runs it as its `initializeCommand`. The devcontainer, integration and signal-cli images take the generated CA through compose's `tls` build context instead of committed copies, and the generated files are gitignored. Committed build output (the `signalctl` binary and root-level logs) is removed and ignored, as are local agent-tooling state files.

## [0.2.2-alpha] - 2026-10-10

### Changed

- `github.com/jeremyhahn/go-qrdb` and `github.com/jeremyhahn/go-qrdb/sdk/go` v0.7.0-alpha → v0.47.0-alpha (#116). The modules go-qrdb v0.47.0-alpha requires move with it, among them go-quicraft v0.20.0, go-truststrap v0.6.0-alpha, go-objstore v0.4.0-alpha, pebble v2.1.7 and quic-go v0.63.0, and go-enclave v0.8.0-alpha is new. The secure package's `Secret.Open`, `NewSecret` and `NewSecretFromBuffer` now take a context, and `Buffer.Bytes` is gone: `SecureString` and the certificates manager read protected bytes through `Buffer.WithBytes` or `secure.CopyOut`, and pass `context.Background()` because their own APIs carry no context. `SecureString.Clone` seals the buffer `Secret.Open` returns instead of copying it into a second buffer under two nested borrows, which v0.47's borrow guard rejects; the value still never leaves protected memory.
- Every binary (signald, cdsi, svr2, registration-service, storage-service, key-transparency and the signal client, desktop GUI included) now owns go-qrdb v0.47's secure-memory process lifecycle through the new `pkg/securemem` (#116). Before anything else runs it hardens the process against inspection (`secure.HardenProcess`; any failure exits non-zero, and the outcome is logged) and installs the process locked-memory budget: 64 MiB, or less when `RLIMIT_MEMLOCK` is bounded below that plus 2 MiB of headroom, refusing to start when the limit leaves under 1 MiB. On an orderly exit it wipes all protected memory within 30 seconds and reports an incomplete wipe as an error. `QRDB_SECURE_ALLOW_PROCESS_INSPECTION=true` leaves a process inspectable for a debugging session, with a warning.
- The secure-memory lifecycle now runs only on the command paths that hold secrets (#116): each binary's root command starts it before loading configuration, the signal client before any account command or the GUI, and the shutdown wipe runs only once it has started. `version`, `help` and `--help` run on any `RLIMIT_MEMLOCK`. Its hardening, budget and wipe records go through the logger each `main` builds (signald's JSON on stdout, the others' text on stderr) instead of Go's default logger; the daemons build that logger in `main` rather than in `start`. `pkg/securemem` exposes `New(logger)`, `Lifecycle.Start` and `Lifecycle.Run` in place of `Run(fn)`, and its unit tests no longer read the host's memlock limit.
- `make lint` now ends with actionlint over `.github/workflows/` (new `make actionlint` target, pinned at `ACTIONLINT_VERSION` v1.7.12; CI's Lint job installs that pin unless the runner already carries it). `make trivy` and `make trivy-image` fail with an install hint when trivy is not on PATH instead of skipping and exiting 0, so `make security` can no longer pass without its scanner (#92).

## [0.2.1-alpha] - 2026-10-09

### Security

- `GET /resources/<name>` can no longer serve files outside the resources root (#68). The containment check reasoned about a lexical path while the reads followed symlinks, so a symlink inside the root was served; static resources are now opened through `os.Root`, which refuses to leave the root, symlinks included. A directory answers 404 (the same as a missing file or an escape) instead of an unauthenticated listing of the tree.
- Credential-bearing path segments — verification session ids, username-link handles and FIDO2 ceremony ids — are redacted from the access log (#40).
- `Destroy` is terminal on the directory and secure-storage credential managers: a setter racing shutdown wipes its own clone and fails instead of installing a live secret nothing would ever wipe (#46).
- An absent secret is now distinguished from an unreadable one under a single lock, so a configured-but-unopenable secret can no longer be treated as unset (#15, parts 1 and 4).
- Two comparisons of protected secrets that went through `Plaintext()` now use `SecureString.Equals` inside the existing `WithBytes` borrow window (#21).
- Production validation rejects the dev CDN placeholders (#19).

### Added

- Bind addresses resolve through four layers, highest first: flag, environment, config file, defaults (#60). Covered bind keys are `health.listen`, `verification.grpcListen`, `svr2.httpListen`, `svr2.wsListen`, `cdsi.wsListen`, `storageService.httpListen` and `keyTransparency.grpcListen`; signald's own listeners, dialers and advertised address are covered too (#101, below). Environment names derive from the key (`SIGNAL_` plus the upper-cased key with `.` as `_`, e.g. `SIGNAL_KEYTRANSPARENCY_GRPCLISTEN`); flag names are the kebab-cased key (e.g. `--key-transparency-grpc-listen`). A flag only overrides when the operator sets it. A required bind address explicitly emptied by file, environment or flag fails config validation (the optional keys in #101 may be empty). The new `health.listen` key (default `0.0.0.0:8099`) configures the health/metrics sidecar of signald, registration-service and key-transparency. API: `config.LoadWithFlags`, `config.AddAddressFlags`, `config.EnvName`, `config.FlagName`, `Config.Address`.
- signald's own addresses resolve through the same layers (#60, #101): the listeners `server.httpListen` and `server.grpcListen`; the dialed endpoints `keyTransparency.remoteAddr`, `verification.remoteAddr`, `storageService.remoteUrl` and `svr2.remoteUrl`; and the advertised attachment upload address `attachments.tusUri`. These are optional, with an empty default, and empty disables the listener or remote path (`Config.Validate` still requires at least one of `server.httpListen` and `server.grpcListen`, and each must be `host:port`). The legacy `server.host`, `server.httpPort` and `server.grpcPort` keys still work: they are folded into the listen addresses only when no layer set the address itself, so a flag, environment variable or `httpListen`/`grpcListen` file key always wins. signald registers the matching flags (e.g. `--server-http-listen`) and `SIGNAL_SERVER_HTTPLISTEN`-style variables.
- `sdk/go`: `Client.ConnectWebSocketSession` returns a channel closed when the session's read loop ends, so a caller can notice a dropped socket; `ConnectWebSocket` keeps its signature and discards the channel (#38).
- `make gosec-tool` builds gosec from the `tools/gosec` module (#94).

### Changed

- `make release-alpha` adopts the handbook template v2 (#59): explicit `VERSION=vX.Y.Z-alpha`, signed annotated tag through `agent-git.sh`, pushes only the release commit and that tag, fails closed, and refuses a version with no CHANGELOG section. The Makefile build variable `VERSION` is renamed `BUILD_VERSION`.
- Go 1.27.2 (#94): `go.mod`, workflows and Dockerfiles move from 1.27.1 to 1.27.2, with `golang.org/x/crypto` v0.57.0, `x/term` v0.46.0, `x/net` v0.60.0, `x/sync` v0.23.0, `x/sys` v0.48.0 and `x/text` v0.42.0. gosec v2.29.0 is built against an `x/tools` that cannot read Go 1.27.2 export data, so `make gosec` now builds it from the `tools/gosec` tool module (gosec v2.29.0 with `x/tools` v0.51.0) into `bin/tools` and fails closed if that build fails. A caller-supplied `GOSEC` is run as-is and skips the build. The `GOSEC_VERSION` pin stays v2.29.0.
- CI tool pins moved to upstream latest, in step with the ci-runner image (#88): golangci-lint v2.13.2 → v2.14.0, govulncheck v1.7.0 → v1.8.0, protoc-gen-go v1.36.11 → v1.36.12, Go 1.26.x → 1.27.1 (`go.mod`, workflows, Dockerfiles; superseded by 1.27.2, #94). gosec stays at v2.29.0, already the latest. The indirect `github.com/cockroachdb/swiss` moves to v0.0.0-20260820225851-333444432258, the first revision that builds on Go 1.27.
- `github.com/spf13/viper` v1.21.0 is a new direct dependency, and `github.com/spf13/pflag` becomes direct (#60).
- Listener fallbacks are gone from the binaries: cdsi, key-transparency, registration-service, storage-service and svr2 no longer substitute a hard-coded address for an empty one, and `health.RunSidecar` returns `health.ErrNoListenAddr` for an empty address instead of binding `0.0.0.0:8099` (#60). The defaults now live in `pkg/config`.
- Removed `IncomingMessageEntity.Timestamp`: no client populates it and the Java `IncomingMessage` has no such field. The bounds check moved onto the message-list timestamp that reaches the client (#34).
- `gosec` and `govulncheck` are pinned and read from the Makefile instead of installed at `@latest` (#51); the devcontainer reads every tool pin from the Makefile (#76). `protoc` and its plugins are pinned, `make proto` fails closed on a mismatch, and the tree is regenerated against the pin (#30).

### Fixed

- Message delivery over the WebSocket sends a serialized `textsecure.Envelope` protobuf in `WebSocketRequestMessage.body` rather than JSON; no real client could read a delivered message before (#20). `MarshalEnvelope` is the single encoder for all three delivery paths; an unmapped envelope type is a typed error instead of a silent downgrade to UNKNOWN, and reserved type 2 is no longer accepted inbound.
- The delivered envelope carried `client_timestamp=0`, so libsignal rejected every message with `InvalidMessageStructureException`; it now takes the timestamp from the message list (#34).
- Profile: `handleSetProfile` follows the Java reference — `{avatar:false, sameAvatar:true}` clears rather than keeps the avatar, the existing avatar is read at the version being written rather than via `GetLatest`, and an existing avatar is carried forward only when it starts with `profiles/` (#21). Residual same-version read-modify-write is tracked in #65 and missing CDN object deletion in #66.
- Re-registering a verified session returns 409 `SESSION_ALREADY_VERIFIED` across REST and gRPC instead of a 429 cooldown (#22).
- A challenge submission with no captcha provider configured returns 503 instead of dereferencing a nil verifier (#18).
- The shipped config seeds the remote-config defaults the integration suite expects (#19, with the production-validation change under Security).
- The desktop `Run` gains a context and a shutdown path, `DAOStore.Close` releases the store it opened, and a failed constructor or close is no longer silent (#55).
- The desktop WebSocket manager reconnects on a dropped socket, with a backoff that doubles from 1s up to 30s and resets only after a session that lasted that long (#38).
- `pkg/workers`: the cron test used `@every 100ms`, which robfig/cron rounds up to one second; it now uses the real granularity and a deadline that fits two periods (#79). Test only.

### CI

- The coverage gate (`make coverage`, new `coverage-gate` target) fails closed on a missing, empty, malformed or header-only profile and on an invalid `COVER_MIN` (#13).
- `lint` and `gosec` analyse the build-tagged packages (#42), and both run a second pass under the `integration` tag (#44, #53); the integration harness verifies the devcontainer certificate instead of skipping TLS. `gosec` is pinned to v2.29.0 with PATH resolution enforced (#73) and bounded to a concurrency of 4.
- The integration suite also runs when `pkg/**`, `cmd/**` or `sdk/**` change.
- Integration and unit test fixes: harness defects that masked ten suite failures (#17), the cleanup test no longer races the sweeper (#49), a vacuous UUID-index test and five load-bearing waits in cdsi (#74), and per-binary `getUserStatus` assertions instead of a shared exit code (#75).
- ci-template v1.15: every job starts at once, push on main only (#87); the label-triggered peer-review and automerge workflows were revised.

## [0.2.0-alpha] - 2026-08-19

MINOR rather than PATCH: this span carries **breaking API changes**, and
pre-1.0 that is where breakage lives (release-versioning.md §1).

### Security

- **Long-lived HMAC shared secrets and issued bearer credentials now live in protected memory**, not ordinary Go heap. Every one of them was previously an unwipeable `[]byte` or `string`, resident for the process lifetime, readable in a core dump and swappable to disk. Covered: `external.GeneratorConfig.Key`, `DirectoryManager` and `SecureStorageManager` shared secrets, the `extservice` storage/svr client secrets, `config.{StorageService,CDSI,SVR2}.SharedSecret`, `Attachments.TusSharedSecret`, and the `DirectoryCredentials` / `StorageCredentials` / `external.Credentials` passwords. (#7, #9, #12, #14)
- **A borrow-scoped accessor.** `SecureString.WithBytes` hands the callback the protected pages themselves under a read lock held across the whole reveal, and `Destroy` takes the write lock — so a wipe waits out the readers in flight instead of unmapping under them. Removing the lock reproduces a real `DATA RACE`.
- **Fail-closed everywhere a secret can go missing.** A secret that cannot be revealed, cloned or protected aborts startup or fails the operation; it never degrades to the legacy random-UUID stub, which issues credentials the peer rejects while looking like success.
- **`Clone` distinguishes "not configured" from "allocation failed".** Conflating them let memory pressure silently downgrade a configured deployment to stub credentials.
- **Credential mode and key are published as one immutable atomic state.** Two independent atomics allowed a rotation to strand HMAC mode with no key (issuance fails permanently) or serve a stub over a live key.
- **Ownership transfer clones first and validates the clone**, closing a check-then-clone TOCTOU at five construction/rotation sites.
- **A failed config load wipes what it had already sealed.** `yaml.v3` populates field by field and reports type errors at the end, so a partially decoded `Config` already owns protected allocations the caller never receives. `Config.Destroy` also gained the missing `Storage.Postgres.URL` — a DSN carries its credentials inline.
- Credentials are assembled and verified in wipeable byte buffers rather than Go strings, which cannot be wiped.

### Added

- `pkg/config/secrets`: `WithBytes`, `NewSecureStringFromBytes`, and a fallible `Clone`.
- `Destroy` on the directory and secure-storage managers, the external credential generator, and the credential types; all wired into the daemon shutdown path and registered at construction so an aborted startup leaves nothing resident.
- Typed `SharedSecretUnavailableError` in `pkg/directory` and `pkg/securestorage`.

### Changed — BREAKING

- `secrets.NewSecureString` returns `(*SecureString, error)`; `Reveal() (string, error)` added alongside `Plaintext()`. (#7)
- `SecureString.Clone` returns `(*SecureString, error)`.
- `external.GeneratorConfig.Key`, `DirectoryCredentials.Password`, `StorageCredentials.Password` and `external.Credentials.Password` are `*secrets.SecureString`.
- `config.{StorageService,CDSI,SVR2}.SharedSecret` are `*secrets.SecureString` — **no YAML schema change**; the same scalar unmarshals, and `kms://` resolution still applies.
- `DirectoryManager.SetSharedSecret` and `SecureStorageManager.SetSharedSecret` return `error`.
- First-party dependencies moved to their latest tags: go-libsignal `v0.1.2-alpha`, go-qrdb and its `sdk/go` `v0.7.0-alpha`, go-codec `v1.4.0`, go-objstore `v0.2.2-alpha`, go-quicraft `v0.6.2-alpha`. go-codec v1.4.0 drops the archived `hamba/avro/v2` and with it three advisories with no fix available (GO-2026-5046/5047/5048). (#6)

### Fixed

- The storage-auth handler never destroyed the credential it issued — one abandoned protected allocation per request once the field became protected.
- The dev-fallback ephemeral signing key was never wiped; unlike the other two branches it is owned by `runStart`, so `cfg.Destroy()` never reached it.

### CI

- `make vet` runs under the repo's build tags **and** again with `integration`: a compile error behind a build tag made "vet clean" true and incomplete at the same time.
- `golangci-lint` pinned to `v2.12.2`. v2.13.0 ships `honnef.co/go/tools v0.8.0-rc.1`, whose `nilness` analyzer panics on the `getsentry/sentry-go` dependency — a crash that produces a red gate with **zero findings**, which reads as "your code is bad". Measured identically on `main` without any of this span's changes.

### Notes

The residual protected-memory gaps deliberately left out of scope — `IsDestroyed` not distinguishing absent from unopenable, `Destroy` not being terminal, and credential material still transiting Go strings at the JSON and Basic-auth boundaries — are tracked in **#15** with fix shape and verification per item.

## [0.1.1-alpha] - 2026-08-13

Retitled from `[Unreleased]`: the entries below were already in the CHANGELOG when
`v0.1.1-alpha` was tagged, and the features they describe are present in that
tag's tree (verified file-by-file), so they shipped in that release and were
simply never moved out of the unreleased section.

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

go-signal is a Go port of the Java Signal-Server reference implementation. The work is tracked in phases in the project plan:

- **Phase 0**: Prerequisites — module resolution, docs scaffold, changelog setup *(current)*.
- **Phase 1**: Foundation — pluggable storage, Redis cache, gRPC scaffold, background worker framework.
- **Phase 2**: Core protocol — PNI, real ZK credentials, PQ keys, message delivery, backups.
- **Phase 3**: Integrations — APNs/FCM, verification transports, CAPTCHA, TURN, attachments, device check.
- **Phase 4**: External services — registration-service, svr2, cdsi, storage-service, key-transparency as separate binaries.
- **Phase 5**: Production readiness — observability, health, multi-instance coordination, hardening, performance.

Each phase contributes an entry to this changelog under its corresponding `[x.y.z]` release.
