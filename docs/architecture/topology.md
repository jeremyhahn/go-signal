# Deployment topology

This document describes the service topology go-signal targets at full parity with the Java `Signal-Server`. We match Java's microservice decomposition: the chat server is one binary, and each Signal infrastructure service is its own binary.

## Target topology

```
                                      ┌────────────────────┐
                                      │   signal clients   │
                                      │ (iOS / Android /   │
                                      │  Desktop / CLI)    │
                                      └──────────┬─────────┘
                                                 │ HTTPS + WebSocket
                                                 │
                                      ┌──────────▼─────────┐
                                      │      signald       │
                                      │  chat / messaging  │
                                      │  (REST + gRPC + WS)│
                                      └──┬───────┬───────┬─┘
                       ┌─────────────────┘       │       └──────────────────┐
                       │ gRPC (mTLS)            gRPC (mTLS)              gRPC (mTLS)
                       │                         │                         │
          ┌────────────▼────────────┐ ┌──────────▼─────────┐ ┌─────────────▼──────────┐
          │  registration-service   │ │   key-transparency │ │     storage-service    │
          │  (Twilio / SES / SMTP)  │ │ (VRF + Merkle log) │ │ (user-manifest store)  │
          └─────────────────────────┘ └────────────────────┘ └────────────────────────┘

                                      ┌────────────────────┐      ┌──────────────────┐
                                      │        svr2        │      │       cdsi       │
                                      │ (SGX + SVR4 +      │      │  (SGX + privacy- │
                                      │  Noise protocol)   │      │  preserving      │
                                      │                    │      │   directory)     │
                                      └────────────────────┘      └──────────────────┘
                                              ▲                          ▲
                                              │ client WebSocket +       │ client gRPC +
                                              │ Noise handshake          │ Noise handshake
                                              │                          │
                                              └──────────────────────────┘
                                                (clients connect directly;
                                                 signald routes credentials)

   ─────────────── shared infrastructure ───────────────

   ┌──────────────────────────┐  ┌───────────────────────┐  ┌──────────────────────┐
   │   persistent storage     │  │     Redis cache       │  │     blob storage     │
   │ go-qrdb | DynamoDB | PG  │  │ (messages, rate limit,│  │ S3 / GCS / Azure /   │
   │                          │  │  pub/sub, challenges) │  │ local filesystem     │
   └──────────────────────────┘  └───────────────────────┘  └──────────────────────┘
```

## Binaries

| Binary                    | Package                 | Purpose                                                                 |
|---------------------------|-------------------------|-------------------------------------------------------------------------|
| `signald`                 | `cmd/signald/`          | Chat and messaging server. REST + gRPC + WebSocket. Coordinates the rest. |
| `registration-service`    | `cmd/registration-service/` | Phone/voice/email verification sessions. Delegates to a pluggable transport (Twilio, SES, SMTP). |
| `svr2`                    | `cmd/svr2/`             | Secure Value Recovery v4. SGX-attested, Noise-wrapped client protocol.  |
| `cdsi`                    | `cmd/cdsi/`             | Contact Discovery Service — privacy-preserving batch phone-number lookup. |
| `storage-service`         | `cmd/storage-service/`  | Per-account encrypted manifest storage (contacts, groups, settings).    |
| `key-transparency`        | `cmd/key-transparency/` | Append-only log with VRF + Merkle consistency proofs.                   |
| `signal`                  | `cmd/signal/`           | Administrative CLI (account lookup, worker invocation, cert ops).       |

## Where this plan currently stands

Today (Phase 0 baseline) only `signald` and `signal` exist. The other five binaries are built in Phase 4 of the port plan. `signald` currently houses stub handlers (`handlers_svr.go`, `handlers_svr2.go`, `handlers_cdsi.go`, `handlers_storage.go`, `handlers_keytransparency.go`) that will be replaced with gRPC clients once the target services are live.

## Shared infrastructure

All binaries share three kinds of infrastructure:

### Persistent key-value storage

`pkg/store.KVClient` defines a single interface implemented by three backends:

- **go-qrdb** — primary, self-contained, no cloud dependency.
- **DynamoDB** — first-class alternate, schema-parity with Java Signal-Server.
- **Postgres** — third option for teams preferring SQL.
- **memory** — test-only.

Selected per binary via the `storage.backend` config key.

### Redis cache

Used for:

- Message queues awaiting persistence (`q:{aci}:{device}`).
- Rate-limit counters (`rl:{limit}:{id}`).
- Message availability flags (`hasMessages:{aci}:{device}`).
- Multi-recipient message (MRM) shared payloads (`mrm:{hash}`).
- Pub/sub for cross-instance WebSocket delivery.
- Leader-election leases for distributed worker execution.

Accessible through `pkg/cache.Client`.

### Blob storage

Used for attachments, message backups, sticker packs. Abstracted through `pkg/storage/blob` with S3, GCS, Azure Blob, and local-filesystem drivers.

## Inter-service communication

- **Transport**: gRPC over mTLS between services.
- **Auth**: HMAC-signed, time-bound service credentials issued via the `ExternalServiceCredentialsGenerator` pattern (ported from Java).
- **Circuit breakers**: Each client wraps its target service in a `gobreaker` circuit breaker.
- **Retries**: Bounded retry with exponential backoff and jitter.

Shared client-side code lives in `pkg/extservice/`.

## Client-facing connections

Signal clients speak:

- **HTTPS** (REST) to `signald`.
- **HTTP/2** (gRPC) to `signald`.
- **WebSocket** to `signald` for real-time message delivery.
- **WebSocket + Noise** directly to `svr2` for backup/restore operations.
- **gRPC + Noise** directly to `cdsi` for directory lookups.

`signald` issues short-lived credentials that clients use to authenticate against `svr2` and `cdsi`.

## Deployment units

- **Development**: `make dev` runs `signald` alone with in-memory storage and no external services. Stub handlers return deterministic mock data.
- **Local full-stack**: `docker-compose up` in `deploy/` spins up all six services plus Redis and a storage backend.
- **Production**: Kubernetes manifests in `deploy/k8s/` deploy each service as an independent StatefulSet with its own scaling and storage policies.

See [deployment/docker-compose.md](../deployment/docker-compose.md) and [deployment/kubernetes.md](../deployment/kubernetes.md) once Phase 4 lands.
