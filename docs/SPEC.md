# go-signal specification

> **Status: DRAFT** · Scope: go-signal · Last verified: 2026-11-12

## Purpose

go-signal is a Signal messaging server written in Go, byte-wire compatible with the Java Signal-Server commit pinned in `SIGNAL_SERVER_REV`.
It sits at the application-service layer: it stores through go-qrdb `sdk/go` (or its own memory, file and Postgres backends) and takes every crypto and wire-format primitive from go-libsignal.
Signal clients consume its REST, gRPC and WebSocket APIs; go-quicbaas consumes it under its `signal` build tag; Go callers use `sdk/go` and the `signal` CLI.

## Boundaries

- Owns: the Signal server API surface (REST, gRPC, WebSocket) and its account, device, key, message, profile, group, username, calling, backup and verification domains.
- Owns: the companion service binaries `registration-service`, `svr2`, `cdsi`, `storage-service` and `key-transparency`.
- Never implements crypto or wire-format primitives; they come from go-libsignal.
- Never reaches into storage engine internals; it uses go-qrdb only through `sdk/go`.
- Never implements payments ([ADR 0003](architecture/decisions/0003-skip-payments.md)).

## Features

| Feature | Status | Requirements | Detail |
|---|---|---|---|
| account-registration | shipped | Verification sessions gate account creation. Registration returns the account identifiers and credentials. Re-registering a verified session returns 409. | docs/verification/ |
| phone-verification | shipped | Codes are delivered through a pluggable transport (Twilio, SES, SMTP under the `smtp` tag). Captcha challenges gate code requests when a provider is configured. | docs/verification/ |
| authentication | shipped | Every device authenticates with Basic auth. Credential-bearing path segments are redacted from the access log. | docs/auth/ |
| fido2-webauthn | shipped | WebAuthn ceremonies register and verify hardware keys. Built only under the `fido2` build tag. | docs/auth/ |
| multi-device | shipped | Devices are linked through provisioning sockets. Each device authenticates on its own. | none |
| prekey-distribution | shipped | EC, signed and KEM pre-keys are stored per device. One-time pre-keys are consumed atomically. | none |
| messaging | shipped | Messages are queued, persisted and delivered as serialized `textsecure.Envelope` protobufs. Multi-recipient payloads are cached. | docs/messaging/ |
| websocket-delivery | shipped | Messages are pushed in real time over the WebSocket. The socket carries keepalive and provisioning. | docs/api/ |
| profiles | shipped | Profiles are versioned. zkgroup profile-key credentials are issued. Avatars follow the Java reference semantics. | none |
| usernames | shipped | Accounts reserve and confirm usernames. Username links resolve to an account. | none |
| groups | shipped | The server stores group state for clients. | none |
| calling | shipped | Call signaling is relayed between devices. Call-quality surveys are accepted. | none |
| backups | shipped | Message-archive backups are served when the backup subsystem is enabled. | none |
| stickers | shipped | Sticker packs are served to clients. | none |
| secure-storage | shipped | Encrypted contact and settings sync is served by the storage service. | none |
| secure-value-recovery | shipped | SVR2 is served by the `svr2` binary. signald reaches it through a configured remote URL. | none |
| contact-discovery | shipped | CDSI is served by the `cdsi` binary. | none |
| key-transparency | shipped | Key transparency is served by the `key-transparency` binary over gRPC. signald reaches it as a client. | none |
| pluggable-storage | shipped | `storage.backend` selects memory, file, Postgres or qrdb. Production mode accepts only Postgres and file. Postgres runs embedded migrations at startup. | docs/storage/ |
| cache | shipped | `cache.backend` selects Redis or in-process memory. The cache carries queues, rate-limit counters and worker leases. | docs/storage/ |
| rate-limiting | shipped | Per-action limits are enforced from a rate-limit registry. | none |
| background-workers | shipped | Scheduled workers run under leases so only one instance runs each job. | docs/workers/ |
| secrets-management | shipped | Secrets resolve from `kms://` URIs, environment references or the `auto` sentinel. Secrets stay in protected memory. | docs/configuration/ |
| secure-memory-lifecycle | shipped | Every binary hardens the process and installs a locked-memory budget before loading configuration. Protected memory is wiped on an orderly exit. | none |
| layered-bind-addresses | shipped | Bind addresses resolve from flag, environment, config file, then defaults. An explicitly emptied required address fails validation. | docs/configuration/ |
| web-ui | shipped | The REST listener serves an embedded web UI and its `/api/v1/` routes. | none |
| desktop-client | shipped | The `signal` client carries a desktop GUI under the `desktop` build tag. The GUI reconnects a dropped WebSocket with backoff. | none |
| health-metrics-sidecar | in progress | signald, registration-service and key-transparency expose health and metrics on a sidecar listener. `health.listen` configures its address. | none |
| credential-strings | in progress | Credentials stay out of Go strings on the REST write and external-auth paths. The gRPC Basic-auth path follows. Every remaining path follows. | none |
| secret-sealing-migration | in progress | Secret sealing moves off the removed go-libsignal Enclave API. | none |
| cdsi-user-status | planned | getUserStatus reaches the CDSI service through a `/cdsi` route. The routing design awaits an architecture decision. | none |
| qrdb-sdk-index-scan | planned | The go-qrdb `sdk/go` bump adopts `*string` IndexScan bounds. | none |

## Interfaces

- SDK: `sdk/go`, a Go client for accounts, devices, messaging, contacts, groups, profiles, stickers, identity, FIDO2 and WebSocket sessions.
- CLI: `signald` (server daemon: `start`, `version`); `signal` (client: register, verify, send, receive, accounts, devices, contacts, groups, profile, identity, stickers, number change, challenge, fido2); `registration-service`, `svr2`, `cdsi`, `storage-service`, `key-transparency` (service daemons).
- API: REST `/v1/` and `/v2/` routes ([api/rest.md](api/rest.md)); gRPC `org.signal.chat.*` services ([api/grpc.md](api/grpc.md)); WebSocket message and provisioning sockets ([api/websocket.md](api/websocket.md)).

## Release criteria

- Credentials are kept out of Go strings on the REST write and external-auth paths ([#47](../../../issues/47)).
- Credentials are kept out of Go strings on the gRPC Basic-auth path ([#77](../../../issues/77)).
- Credentials are kept out of Go strings on every remaining path ([#78](../../../issues/78)).
- `main` is green, with golangci-lint pinned to the runner image ([#84](../../../issues/84)).
- Integration Gate and Integration Tests are green on `main` and post status ([#64](../../../issues/64)).
- Release readiness for public release is confirmed ([#85](../../../issues/85)).
