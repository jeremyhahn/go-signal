# Package Map

> **Status: REFERENCE** · Last verified: 2026-10-09
> Every top-level directory under `cmd/`, `pkg/`, `internal/`, `sdk/`, `frontend/`, `deploy/` and `test/`, with its role.

[overview.md](overview.md) explains how the layers fit together.

## Commands (`cmd/`)

| Package | Description |
|---------|-------------|
| `cmd/signald/` | Server daemon (cobra commands: `start`, `version`) |
| `cmd/signal/` | Client CLI; launches the desktop GUI path when built with the `desktop` tag and run without subcommands |
| `cmd/cdsi/` | Contact discovery service (standalone) |
| `cmd/svr2/` | Secure value recovery service (standalone) |
| `cmd/key-transparency/` | Key-transparency query service (standalone) |
| `cmd/registration-service/` | Verification session service (standalone) |
| `cmd/storage-service/` | Encrypted manifest storage service (standalone) |

See [topology.md](topology.md) for how the binaries relate.

## Protocol layer

| Package | Description |
|---------|-------------|
| `pkg/api/rest/` | REST handlers, middleware, web-UI routes and the SPA catch-all |
| `pkg/api/grpc/` | gRPC server, interceptors, protos and generated code, service implementations |
| `pkg/api/websocket/` | HTTP upgrade handlers for the messaging and provisioning WebSockets |
| `pkg/websocket/` | WebSocket `SessionManager` and the `wsproto` envelopes |

## Service layer

| Package | Description |
|---------|-------------|
| `pkg/service/` | Service interfaces that every protocol handler calls |

## Domain packages

| Package | Description |
|---------|-------------|
| `pkg/accounts/` | Account types, manager and stores |
| `pkg/attachments/` | Attachment (CDN content) storage |
| `pkg/auth/` | Authentication primitives, including the registration lock |
| `pkg/backups/` | Message-archive backup subsystem |
| `pkg/calling/` | Call signaling, TURN provider, quality surveys |
| `pkg/captcha/` | Challenge and CAPTCHA verification for rate-limit relief |
| `pkg/certificates/` | Delivery certificates and group credentials |
| `pkg/devicecheck/` | Device checks (`apple/`) |
| `pkg/devices/` | Device provisioning and linking |
| `pkg/directory/` | Contact-discovery account directory |
| `pkg/fido2/` | WebAuthn/FIDO2 (build tag `fido2`) |
| `pkg/groups/` | Groups v2 types and storage interfaces |
| `pkg/keys/` | Pre-key types, validation and stores |
| `pkg/keytransparency/` | Key-transparency manager (plus `server/`) |
| `pkg/messages/` | Message types, queue, persister, multi-recipient cache, reports |
| `pkg/profiles/` | Profiles |
| `pkg/push/` | Push notification delivery |
| `pkg/registration/` | Registration: `core/`, `sessionshim/`, `recoverypassword/` |
| `pkg/remoteconfig/` | Dynamic feature flags |
| `pkg/securestorage/` | Encrypted manifest storage |
| `pkg/securevaluerecovery/` | SVR credentials |
| `pkg/spam/` | Spam and registration-fraud checks |
| `pkg/stickers/` | Sticker packs |
| `pkg/usernames/` | Username reservation, confirmation and links |
| `pkg/verification/` | Verification sessions and transports (`factory/`, `twilio/`, `ses/`, `smtp/`) |

## External-service back ends

| Package | Description |
|---------|-------------|
| `pkg/cdsi/` | Contact-discovery server state machine |
| `pkg/svr2/` | SVR server state machine and storage |
| `pkg/attestation/` | Pluggable enclave attestation |
| `pkg/extservice/` | Chat-server clients for the external services (`common/`, `registration/`, `keytransparency/`, `storage/`, `svr/`) |

## Infrastructure

| Package | Description |
|---------|-------------|
| `pkg/audit/` | Structured audit-event sink |
| `pkg/cache/` | Cache client interface (`redis/`, `memory/`) |
| `pkg/config/` | YAML configuration loading and validation (`secrets/` holds the secret types and resolvers) |
| `pkg/errors/` | Shared typed errors |
| `pkg/health/` | `/healthz` and `/readyz` probes |
| `pkg/jobs/` | Scheduled-jobs subsystem |
| `pkg/limits/` | Token-bucket rate limiting |
| `pkg/metrics/` | Prometheus instrumentation |
| `pkg/storage/` | Domain store implementations: `memory/`, `postgres/`, `qrdb/`, `blob/` |
| `pkg/store/` | `KVClient` interface and memory, file and failing implementations |
| `pkg/tracing/` | Request-ID and W3C `traceparent` propagation |
| `pkg/version/` | Semantic version parsing and comparison |
| `pkg/workers/` | Background worker framework |

## Client side

| Package | Description |
|---------|-------------|
| `pkg/daostore/` | GenericDAO factory and entities for the local client database |
| `pkg/desktop/` | Desktop client (build tag `desktop`): `bindings/`, `calling/`, `events/`, `jobs/`, `media/`, `ws/` |
| `sdk/go/` | Go client SDK |
| `frontend/` | React web UI source |
| `internal/frontend/` | Embedded web UI assets |

## Deployment and tests

| Path | Description |
|---------|-------------|
| `deploy/` | Dockerfiles, `docker-compose.yml`, `k8s/` manifests |
| `test/integration/` | Integration tests (`api/`, `cli/`, `storage/`, `mocks/`) |
| `test/performance/` | Benchmark documentation |
| `test/tls/` | TLS certificate fixtures |
| `test/signal-cli/` | signal-cli test harness |
| `test/build/` | Security and coverage gate tests |
