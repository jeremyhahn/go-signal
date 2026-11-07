# go-signal Architecture

This document gives an operator-facing tour of the deployed system. For
phase-by-phase implementation history, see [CHANGELOG.md](CHANGELOG.md).

## Topology

Six binaries plus two infrastructure dependencies. signald is the only
public entry point; every other binary sits behind it on the cluster
network.

```
                    ┌─────────────────────────────────┐
                    │  Mobile clients (Signal apps)   │
                    └────────────┬────────────────────┘
                                 │ HTTPS / WebSocket / WS+Noise
              ┌──────────────────┼──────────────────┐
              │                  │                  │
              ▼                  ▼                  ▼
       ┌──────────┐        ┌───────┐         ┌─────────┐
       │ signald  │        │ svr2  │         │  cdsi   │
       │ :8080    │        │ :8092 │         │ :8094   │
       │ :8443g   │        │  WS   │         │  WS     │
       └────┬─────┘        └───┬───┘         └────┬────┘
            │                  │                  │
            │  gRPC            │  HTTP admin      │  gRPC
            │  HTTP admin      │  (DELETE)        │  DirectoryService
            ▼                  ▼                  │
  ┌────────────────┐    ┌─────────────┐           │
  │ registration-  │    │  storage-   │           │
  │ service :8090g │    │  service    │           │
  └────────────────┘    │  :8096      │           │
  ┌────────────────┐    └─────────────┘           │
  │ key-           │                              │
  │ transparency   │                              │
  │ :8098 gRPC     │ ◀────signald reads───────────┘
  └────────────────┘
            ▲                  ▲                  ▲
            │                  │                  │
            └──────────────────┴──────────────────┘
                               │
                  ┌────────────┴───────────┐
                  ▼                        ▼
          ┌─────────────┐          ┌──────────────┐
          │   Redis     │          │  Postgres    │
          │   :6379     │          │  :5432       │
          │ (cluster +  │          │ (durable     │
          │ pub/sub +   │          │  storage)    │
          │ rate-limit) │          │              │
          └─────────────┘          └──────────────┘
```

| Binary | Public? | Wire | Role |
|---|---|---|---|
| `signald` | yes (8080 REST, 8443 gRPC) | HTTPS / WS / gRPC | The chat server. REST + WebSocket + gRPC surfaces mobile clients hit. Talks to every external service. |
| `registration-service` | no | gRPC :8090 | Verification-session lifecycle, SMS/voice code dispatch, per-session rate limits. signald is a gRPC client. |
| `svr2` | yes (8092 WS) | WS + Noise NKhfs | SVR4 secret-recovery state. Mobile clients connect directly via Noise NKhfs over WebSocket. signald only calls the admin DELETE (8091). |
| `cdsi` | yes (8094 WS) | WS + Noise NKhfs | Contact discovery batch lookup. Mobile clients connect directly. signald exposes a DirectoryService gRPC stream cdsi loads at startup. |
| `storage-service` | yes (8096 HTTPS) | HTTPS + HMAC Basic | Encrypted user-manifest blob storage. Mobile clients connect directly. signald calls the admin DELETE. |
| `key-transparency` | no | gRPC :8098 | Append-only key log with Merkle inclusion proofs + ed25519 tree-head signing. signald is a gRPC client. |

Every binary additionally exposes `/healthz`, `/readyz`, and
`/metrics` on a dedicated admin port (`:8099` for the gRPC-native
binaries, the main HTTP port for the HTTP-native ones).

## Inter-service authentication

Mobile clients connecting to svr2 / cdsi / storage-service present
HTTP Basic credentials. The password is
`hex(HMAC-SHA256(sharedSecret, accountUUID))` — signald mints the
credential through `pkg/securestorage`, `pkg/securevaluerecovery`, and
`pkg/directory`'s `GetAuth` paths. Every external service validates
inbound credentials via `pkg/extservice/common.ValidateBasicAuth`
against the same shared secret. Rotating a secret means rotating both
the signald-side mint and the external service's verify key at once.

signald-to-external-service calls use either:
- **gRPC over mTLS** (registration-service, key-transparency,
  signald's outbound DirectoryService consumer cdsi) — production
  certs land via `pkg/extservice/common.TLSConfig`.
- **HTTPS + HMAC Basic** (svr2 admin, storage-service admin) — same
  credential shape as mobile clients, signald acts as a privileged
  client.

## Storage

| Domain | Backend | Notes |
|---|---|---|
| Accounts, messages, sessions, devices, keys, profiles, etc. | Postgres + qrdb (pluggable via `pkg/store.KVClient`) | Memory backend ships for dev / unit tests. |
| WebSocket session clustering + rate-limit token buckets | Redis | Cross-replica pub/sub via `cache.Client.Subscribe`. |
| svr2 SVR4 records | qrdb (production) / in-memory (dev) | Per-identity JSON blobs, optional sealed-at-rest. |
| cdsi directory snapshot | in-memory only | Re-loaded from signald's DirectoryService at boot. |
| storage-service manifests | qrdb / in-memory | Pluggable via `pkg/securestorage.ManifestStore`. |
| key-transparency log | in-memory only | Merkle-tree append-only log; durable backing is a focused follow-up. |

In monolithic deployments (`storageService.remoteUrl` empty) signald runs the
storage-service in-process and serves the `/storage/...` manifest, read, and
write routes itself instead of pointing clients at a standalone binary.

## Observability

Every binary exposes:

- **`/metrics`** — Prometheus format, includes `service="<binary>"`
  constant label so multi-service scrapes stay distinguishable.
  Built-in instrumentation:
  - `http_server_requests_total{method,route,status,service}`
  - `http_server_request_duration_seconds_bucket{method,route,service}`
  - `http_server_inflight_requests{service}`
  - `grpc_server_requests_total{grpc_service,grpc_method,grpc_code,service}`
  - `grpc_server_request_duration_seconds_bucket{...}`
  - Standard `process_*` + `go_*` collectors.
- **`/healthz`** — liveness; reports `alive=false` during graceful
  shutdown so kubelet drains traffic before the listener closes.
- **`/readyz`** — readiness; aggregates registered backend checks
  (cache ping, downstream gRPC channel state, etc.). 503 with the
  failing check's error message in the JSON body.
- **W3C `traceparent`** — `pkg/tracing.HTTPMiddleware` parses inbound
  headers, mints fresh ones when absent, attaches to the request
  context. Spans flow through `pkg/tracing.Recorder` → `Exporter`
  (stdout JSON until the OTel SDK ships).
- **Structured audit events** — `pkg/audit.Logger` emits one JSON
  record per sensitive operation (`ChangeNumber`, `DeleteAccount`,
  `LinkDevice`, `SetRegistrationLock`) with action / outcome / actor /
  details. Production deployments wire a dedicated audit sink so
  records outlive normal log-rotation policies.

## Deployment

`deploy/docker-compose.yml` brings up the full topology for local
development. Each binary has its own `deploy/Dockerfile.<name>` — all
multi-stage, all `CGO_ENABLED=0`, all final image
`gcr.io/distroless/static-debian12:nonroot`.

`deploy/k8s/` ships Kustomize-based manifests:

- `namespace.yaml` — the `signal` namespace.
- `secrets.yaml` — shared HMAC secrets. Production deployments swap
  this for SealedSecrets / external-secrets-operator.
- `postgres.yaml` — StatefulSet + headless Service + PVC.
- `redis.yaml` — Deployment + Service.
- `signald.yaml` — Deployment with `replicas: 2`, RollingUpdate, env
  vars sourced from the Secret.
- `services.yaml` — five external Services + Deployments in one file.
- `kustomization.yaml` — `kubectl apply -k deploy/k8s/` to bring up.

## Operational signals

| Signal | Meaning | Response |
|---|---|---|
| `/readyz` 503 on signald | Cache backend or a downstream service is unhealthy | Check `body.checks.<failing>` to identify; restart the dependency or wait for self-heal. |
| `/healthz` 503 | Process is in graceful shutdown | Wait for replacement pod to come up. |
| `http_server_request_duration_seconds` p99 climbing | Backend slow path | Check downstream `/metrics`. |
| Audit `outcome="denied"` spike | Possible credential-stuffing / authz probing | Filter audit log by source IP. |

## Phase history

The complete delivery history (Phases 0–5) lives in the
plans/fluttering-kindling-flask.md roadmap. Six binaries shipped in
Phase 4; production-readiness primitives (metrics, tracing, health
probes, audit, Redis-backed rate-limits, multi-instance coordination)
shipped in Phase 5.
