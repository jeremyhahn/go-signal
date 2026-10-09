# Deployment topology

> **Status: REFERENCE** · Last verified: 2026-10-09
> The binaries go-signal builds, how they talk to each other, and how `deploy/` runs them.

Like the Java Signal-Server, the chat server is one binary and each Signal infrastructure service is its own binary. The decision is recorded in [ADR-0002](decisions/0002-external-services-as-separate-binaries.md).

```
 clients --REST / gRPC / WebSocket--> signald --gRPC--------------> registration-service
    |                                   |  \--gRPC----------------> key-transparency
    |                                   |  \--HTTP + HMAC (admin)--> svr2
    |                                   |  \--HTTP + HMAC (admin)--> storage-service
    |                                   ^
    |                                   |  gRPC (DirectoryService)
    +--WebSocket + Noise--> svr2        |
    +--WebSocket + Noise--> cdsi -------+
    +--HTTPS--------------> storage-service
```

Every external service is optional for signald. Without a remote address configured, signald runs the registration engine in process, serves the storage endpoints itself, and uses the in-process key-transparency manager. The remote settings are `verification.remoteAddr`, `storageService.remoteUrl`, `keyTransparency.remoteAddr` and `svr2.remoteUrl`.

## Binaries

| Binary | Package | Purpose | Client-facing protocol |
|---|---|---|---|
| `signald` | `cmd/signald/` | Chat server: REST, gRPC and WebSocket | REST, gRPC, WebSocket |
| `registration-service` | `cmd/registration-service/` | Verification sessions: lifecycle, code generation, per-session rate limits, transport delivery | gRPC (`RegistrationService`), called by signald |
| `key-transparency` | `cmd/key-transparency/` | Hosts the `KeyTransparencyQueryService` gRPC contract; signald reads from it for the key-transparency REST endpoints | gRPC |
| `svr2` | `cmd/svr2/` | SVR4 state machine over a Noise NKhfs-encrypted WebSocket; clients connect to it directly | WebSocket + Noise |
| `cdsi` | `cmd/cdsi/` | Contact discovery v2 over a Noise NKhfs-encrypted WebSocket; clients connect to it directly | WebSocket + Noise |
| `storage-service` | `cmd/storage-service/` | Per-account encrypted manifest and item storage; JSON over HTTPS with HMAC Basic auth; clients connect to it directly | HTTPS |
| `signal` | `cmd/signal/` | Client CLI and desktop entry point | n/a |

Build the service binaries with `make build-services`, or one at a time with `make build-cdsi`, `build-svr2`, `build-key-transparency`, `build-registration-service`, `build-storage-service`.

## What signald does for each service

| Service | signald's role |
|---|---|
| `registration-service` | With `verification.remoteAddr` set, a gRPC client (`pkg/extservice/registration/grpcclient`). Otherwise the same engine (`pkg/registration/core`) runs in process. The captcha gate stays in signald (`pkg/registration/sessionshim`); the service does not know about captcha state. |
| `key-transparency` | With `keyTransparency.remoteAddr` set, a gRPC client (`pkg/extservice/keytransparency`) over TLS 1.2 or later, or plaintext when `keyTransparency.remoteInsecure` is set. |
| `svr2` | Issues HMAC credentials at `/v2/svr/auth` and calls the service's admin `DELETE /v1/delete` when an account is deleted. It does not proxy SVR traffic. |
| `cdsi` | Issues HMAC credentials at `/v2/directory/auth`, which clients present as HTTP Basic on the WebSocket upgrade. At startup cdsi opens a gRPC channel to signald's `DirectoryService` and streams the directory snapshot into its in-memory index. |
| `storage-service` | Issues credentials at `/v1/storage/auth` and calls the admin `DELETE /v1/storage` on account deletion. When `storageService.remoteUrl` is empty, signald serves the storage endpoints itself from its own manifest store; when it is set, signald's storage endpoints stay on a `204` stub. |

## Inter-service communication

Shared client-side code is in `pkg/extservice/common`:

- **Credentials**: `BasicAuthHeader` builds an HTTP Basic header whose password is the hex HMAC-SHA256 of the identity under a shared secret; `ValidateBasicAuth` checks it in constant time. This mirrors the Java `ExternalServiceCredentialsGenerator`.
- **TLS**: `TLSConfig` takes an optional CA file and an optional client certificate and key; setting both enables mTLS. `MinVersion` defaults to TLS 1.2 and can be raised to 1.3. `Insecure` permits a plaintext channel for development and compose.
- **Retries**: `RetryConfig` retries with exponential backoff and jitter. Defaults are 3 attempts, 200 ms initial backoff and a 5 s cap.

There is no circuit breaker in `pkg/extservice`.

## Shared infrastructure

### Persistent storage

`storage.backend` selects `memory` (default), `file`, `postgres` or `qrdb`. The `qrdb` value runs on an in-process fake, and `dynamodb` is not implemented. See [overview.md](overview.md#storage).

### Cache

`cache.backend` selects `redis` or the in-process memory cache, behind `pkg/cache.Client`. Redis holds:

- per-device message queues, key `q:{uuid}:{device}` with a side hash `qm:{uuid}:{device}`;
- multi-recipient shared payloads, key `mrm::{uuid}`;
- rate-limit counters, prefix `ratelimit:`;
- cross-instance WebSocket wake-ups, channel prefix `signal:ws:notify:`;
- worker leases, prefix `workers:lease:`.

[../storage/redis-keys.md](../storage/redis-keys.md) has the full layout.

### Blob storage

Attachments go through `pkg/storage/blob`, which has a filesystem driver (`filesystem.go`) and an S3 driver (`s3/`).

## Deployment units

`deploy/` holds one Dockerfile per binary (`Dockerfile.signald`, `.cdsi`, `.svr2`, `.key-transparency`, `.registration-service`, `.storage-service`) and a shared one (`Dockerfile.shared`).

- **Development**: `make dev` runs `go run ./cmd/signald/ start`, which uses the default `memory` storage and cache unless the configuration says otherwise.
- **Compose**: `deploy/docker-compose.yml` runs `redis`, `postgres`, `registration-service`, `svr2`, `cdsi`, `storage-service`, `key-transparency` and `signald`.
- **Kubernetes**: `deploy/k8s/` has a kustomization with a namespace, `signald.yaml`, `services.yaml` (a `Service` and a single-replica `Deployment` for each of the five services), `redis.yaml`, `postgres.yaml` and `secrets.yaml`. See `deploy/k8s/README.md`.

See also [../deployment/](../deployment/).
