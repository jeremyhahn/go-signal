# Architecture Overview

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of how go-signal is layered, which backends it can run on, and which build tags it supports.

go-signal is a Go implementation of the Signal server. It targets wire compatibility with the Java [Signal-Server](https://github.com/signalapp/Signal-Server) at the commit pinned in `SIGNAL_SERVER_REV`.

```
Module:  github.com/jeremyhahn/go-signal
Go:      1.27.4 (go.mod)
License: AGPL-3.0
```

## Layers

```
  +---------------------------------------+
  |            Protocol layer             |
  |   REST  /  gRPC  /  WebSocket         |
  +-------------------+-------------------+
                      |
  +-------------------v-------------------+
  |      Service layer  (pkg/service)     |
  |   one interface per API-facing domain |
  +-------------------+-------------------+
                      |
  +-------------------v-------------------+
  |   Domain packages (accounts, keys,    |
  |   messages, profiles, devices, ...)   |
  +-------------------+-------------------+
                      |
  +-------------------v-------------------+
  |         Stores and cache clients      |
  +---------------------------------------+
```

A request is parsed and authenticated by a protocol handler, passed to a `pkg/service` interface, and executed by the domain package behind it. The domain package reads and writes through a store interface that it defines.

### Protocol layer

| Package | Protocol | Notes |
|---|---|---|
| `pkg/api/rest/` | REST over HTTP (TLS when `server.tlsCertFile` and `server.tlsKeyFile` are set) | Signal-compatible `/v1/...` and `/v2/...` routes, plus the web-UI `/api/v1/...` routes. See [api/rest.md](../api/rest.md). |
| `pkg/api/grpc/` | gRPC | `org.signal.chat.*` services; one routing interceptor. See [api/grpc.md](../api/grpc.md). |
| `pkg/api/websocket/` | WebSocket | Message delivery and provisioning sockets, mounted on the REST listener. See [api/websocket.md](../api/websocket.md). |

`cmd/signald` starts the REST server always, and the gRPC server only when `server.grpcPort` is non-zero.

### Service layer

`pkg/service` holds the interfaces that protocol handlers call. Each is implemented once and shared by every transport:

| Interface | File |
|---|---|
| `AccountService` | `accounts.go` |
| `MessageService` | `messages.go` |
| `KeyService` | `keys.go` |
| `ProfileService` | `profiles.go` |
| `CertificateService` | `certificates.go` |
| `DeviceService` | `devices.go` |
| `UsernameService` | `usernames.go` |
| `CallSignalingService`, `CallingService` | `calling.go`, `calling_manager.go` |
| `BackupService` | `backups.go` |
| `DirectoryService` | `directory.go` |
| `SecureStorageService` | `securestorage.go` |
| `StickersService` | `stickers.go` |
| `KeyTransparencyService` | `keytransparency.go` |
| `RecoveryPasswordService` | `recoverypassword.go` |

`SignalService` (`signal.go`) aggregates `Accounts`, `Messages`, `Keys`, `Profiles`, `Certificates`, `Devices`, `Usernames`, `CallSignaling` and, when the backup subsystem is enabled, `Backups`.

The REST `Server` holds these interfaces. It also holds a few collaborators directly, for example the captcha managers, the remote-config manager, the SVR manager, the rate-limit registry, the attachment store and the report store.

### Domain packages

| Package | Responsibility |
|---|---|
| `pkg/accounts/` | Account lifecycle |
| `pkg/devices/` | Linked devices |
| `pkg/keys/` | Pre-keys |
| `pkg/messages/` | Message queueing, persistence, multi-recipient cache |
| `pkg/profiles/` | Profiles |
| `pkg/usernames/` | Usernames and username links |
| `pkg/groups/` | Groups |
| `pkg/certificates/` | Sender and server certificates |
| `pkg/calling/` | Call signaling and quality surveys |
| `pkg/keytransparency/` | Key-transparency client |
| `pkg/backups/` | Message-archive backups |
| `pkg/verification/` | Verification sessions and code delivery |
| `pkg/fido2/` | WebAuthn (build tag `fido2`) |
| `pkg/websocket/` | WebSocket `SessionManager` |

[package-map.md](package-map.md) lists every package.

## Storage

### Domain stores

Each domain package declares the store interface it needs. `cmd/signald` selects the implementation from `storage.backend`:

| `storage.backend` | Implementation | Notes |
|---|---|---|
| `memory` (default) | `pkg/storage/memory` | Lost on restart. |
| `file` | `store.FileKVClient` under `storage.file.dataDir` (default `data`), with the domain `store_kv.go` implementations and `pkg/storage/qrdb` stores on a `KVClient` adapter | Durable. |
| `postgres` | `pkg/storage/postgres` | Durable. Implements the domain interfaces directly with SQL, not through `KVClient`. Runs embedded migrations at startup. |
| `qrdb` | `pkg/storage/qrdb` over an in-process fake KV store | Not durable; startup wires no real qrdb transport. |

`dynamodb` is not implemented; an unknown or `dynamodb` value falls through to `memory`. Production mode (`mode: production`) accepts only `postgres` and `file`.

### KVClient

`pkg/store/kv.go` defines the key-value interface that the `file` backend and the `store_kv.go` implementations use:

```go
type KVClient interface {
    Put(ctx context.Context, key string, value []byte) error
    Get(ctx context.Context, key string) ([]byte, error)
    Delete(ctx context.Context, key string) error
    DeleteIfPresent(ctx context.Context, key string) (bool, error)
    List(ctx context.Context, prefix string) ([]string, error)
    Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error
    Exists(ctx context.Context, key string) (bool, error)
}
```

`DeleteIfPresent` is atomic and reports whether this call removed the key; one-time pre-key consumption depends on it. Implementations: `MemoryKVClient` (`kv_memory.go`), the file-backed client (`kv_file.go`) and a failure-injecting wrapper (`kv_failing.go`).

Missing and duplicate keys are reported with the typed errors `*store.KeyNotFoundError` and `*store.KeyExistsError`.

### Key prefixes

KV keys start with `signal/<domain>/`. The prefixes in the code:

| Prefix | Owner |
|---|---|
| `signal/accounts/` (`by-number/`, `by-pni/`) | `pkg/accounts` |
| `signal/keys/` (`ec/`, `signed/`, `kem/`, `kem_last_resort/`) | `pkg/keys` |
| `signal/messages/` | `pkg/messages` |
| `signal/reports/`, `signal/reports-by-reporter/` | `pkg/messages` |
| `signal/profiles/` | `pkg/profiles` |
| `signal/verification/` | `pkg/verification` |
| `signal/fido2/creds/` (`by-account/`), `signal/fido2/sessions/` | `pkg/fido2` |

### Cache

`pkg/cache.Client` is selected by `cache.backend`: `redis` (`pkg/cache/redis`) or the in-process default (`pkg/cache/memory`). The key layouts are in [../storage/redis-keys.md](../storage/redis-keys.md). The cache carries the message queues, multi-recipient payloads, rate-limit counters, WebSocket wake-up messages and worker leases.

## Protocol primitives

Cryptography and wire-format primitives come from `github.com/jeremyhahn/go-libsignal`. go-signal does not implement them. The server is Pure Go (no cgo).

## Build tags

| Tag | Effect |
|---|---|
| `fido2` | WebAuthn: `pkg/fido2`, FIDO2 routes, the fido2 stores, `cmd/signald/start_fido2.go` |
| `smtp` | Compiles `pkg/verification/smtp` |
| `desktop` | The desktop client packages under `pkg/desktop` and `cmd/signal/gui_desktop.go`. See [desktop-client.md](desktop-client.md). |

`codec_json` and `qrdb_fts` are build tags of the go-qrdb dependency; the Makefile passes them with the defaults. The Makefile enables `fido2`, `desktop`, `codec_json` and `qrdb_fts` by default (`WITH_FIDO2`, `WITH_DESKTOP`, `WITH_FTS`) and `smtp` only with `WITH_SMTP=1`.

```bash
make build                  # signald and signal, default tags
make build-all              # frontend, then signald and signal
make build WITH_SMTP=1      # also compile the SMTP transport
make build-services         # cdsi, svr2, key-transparency, registration-service, storage-service
make build-desktop          # tags fido2,desktop,codec_json (+ qrdb_fts)
```

## Package layout

```
cmd/
  signald/              server daemon (cobra: start, version)
  signal/               client CLI (and desktop entry point)
  cdsi/ svr2/ key-transparency/ registration-service/ storage-service/
                        standalone service binaries (see topology.md)
pkg/                    see package-map.md
internal/frontend/      embedded web UI
sdk/go/                 Go client SDK
frontend/               React web UI source
deploy/                 Dockerfiles, docker-compose.yml, k8s manifests
test/                   integration, performance, TLS fixtures, signal-cli harness, build gates
```

## Configuration

`signald` reads a YAML file. See [../configuration/reference.md](../configuration/reference.md) for every key and [../configuration/secrets.md](../configuration/secrets.md) for how secrets are held.
