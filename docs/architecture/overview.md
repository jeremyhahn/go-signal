# Architecture Overview

go-signal is a Go implementation of the Signal messaging server protocol. It
targets protocol-level compatibility with the
[Java Signal-Server](https://github.com/signalapp/Signal-Server) reference
implementation.

```
Module:  github.com/jeremyhahn/go-signal
Go:      1.26
License: AGPL-3.0
```

## Three-Layer Architecture

The codebase follows a strict three-layer separation. Protocol handlers never
touch storage directly, and stores never contain business logic.

```
  +---------------------------+
  |      Protocol Layer       |
  |   REST / gRPC / WebSocket |
  +------------+--------------+
               |
  +------------v--------------+
  |       Manager Layer       |
  |      Business Logic       |
  +------------+--------------+
               |
  +------------v--------------+
  |        Store Layer        |
  |    KVClient Persistence   |
  +---------------------------+
```

Requests flow top-down. A REST handler parses the HTTP request, calls a manager
method, and formats the response. The manager validates inputs, applies business
rules, and reads or writes through a store. The store delegates to a `KVClient`
backend.

---

## Protocol Layer

The protocol layer exposes the server over three transports. Each transport
parses requests, authenticates callers, and delegates to the manager layer. No
business logic lives here.

| Package              | Protocol  | Description                          |
|----------------------|-----------|--------------------------------------|
| `pkg/api/rest/`      | REST      | HTTP/2 endpoints, Signal-compatible  |
| `pkg/api/grpc/`      | gRPC      | Protobuf services, unary interceptors|
| `pkg/api/websocket/` | WebSocket | Real-time message delivery           |

REST endpoints follow the `/v1/{resource}` convention for Signal client
compatibility. gRPC services are generated from `.proto` definitions in
`pkg/api/grpc/proto/`. WebSocket connections handle persistent client sessions
for message push.

All three protocols run concurrently from a single server binary.

---

## Manager Layer

Managers contain all business logic, validation, and cross-cutting
orchestration. They are shared across protocol handlers so behavior stays
consistent regardless of transport.

| Package                  | Manager                | Responsibility                    |
|--------------------------|------------------------|-----------------------------------|
| `pkg/accounts/`          | AccountsManager        | Account lifecycle, device linking |
| `pkg/keys/`              | KeysManager            | Pre-key bundles, signed pre-keys  |
| `pkg/messages/`          | MessagesManager        | Message sending, storage, delivery|
| `pkg/profiles/`          | ProfilesManager        | Profile retrieval and updates     |
| `pkg/verification/`      | VerificationManager    | Phone number verification flows   |
| `pkg/fido2/`             | FIDO2AccountsManager   | WebAuthn ceremonies (build-tagged)|
| `pkg/groups/`            | GroupsManager          | Group creation, membership        |
| `pkg/devices/`           | DevicesManager         | Multi-device management           |
| `pkg/certificates/`      | CertificatesManager    | Delivery certificates             |
| `pkg/keytransparency/`   | KeyTransparencyManager | Key transparency auditing         |
| `pkg/calling/`           | CallingManager         | Voice/video calling               |
| `pkg/websocket/`         | SessionManager         | WebSocket session management      |

---

## Store Layer

The store layer is built on the `KVClient` interface defined in
`pkg/store/kv.go`. Every store implementation wraps a `KVClient` for actual
persistence.

```go
type KVClient interface {
    Put(ctx context.Context, key string, value []byte) error
    Get(ctx context.Context, key string) ([]byte, error)
    Delete(ctx context.Context, key string) error
    List(ctx context.Context, prefix string) ([]string, error)
    Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error
    Exists(ctx context.Context, key string) (bool, error)
}
```

### Storage Backends

| Backend           | Implementation         | Use Case                    |
|-------------------|------------------------|-----------------------------|
| In-memory         | `store.MemoryKVClient` | Tests, standalone operation |
| File-backed       | File-based KVClient    | Single-node persistence     |
| QuicBaaS TenantKV | `TenantKVClient`      | Distributed, multi-tenant   |

The in-memory backend (`pkg/store/kv_memory.go`) provides a thread-safe
`map[string][]byte` with deep-copy semantics on reads and writes.

### Key Prefix Convention

All keys follow a hierarchical prefix scheme:

```
signal/{domain}/{resource-type}/{identifier}
```

Examples:

| Prefix                            | Owner                  |
|-----------------------------------|------------------------|
| `signal/fido2/creds/`             | FIDO2 credentials      |
| `signal/fido2/creds/by-account/`  | FIDO2 credential index |
| `signal/fido2/sessions/`          | FIDO2 ceremony sessions|
| `signal/verification/`            | Verification sessions  |

This convention enables efficient prefix-based listing and scanning, and
provides clear namespace separation between subsystems.

### Typed Errors

Storage operations use typed errors exclusively (never `fmt.Errorf`):

| Error              | Meaning                                     |
|--------------------|---------------------------------------------|
| `KeyNotFoundError` | The requested key does not exist             |
| `KeyExistsError`   | The key already exists (used by create-only) |

---

## Signal Protocol Compliance

go-signal implements the Signal messaging protocol using the `go-libsignal`
library:

- **X3DH** - Extended Triple Diffie-Hellman key agreement
- **Double Ratchet** - Per-message encryption with forward secrecy
- **SenderKey** - Efficient group messaging
- **Sealed Sender** - Metadata protection
- **Zero-Knowledge Groups** - Privacy-preserving group membership via zkgroup
- **Secure Value Recovery (SVR)** - PIN-based secret recovery

The server manages pre-key bundles, signed pre-keys, and identity keys through
the keys subsystem. Message routing, storage, and delivery are handled by the
messages subsystem.

---

## Build Tag Extensions

The base binary includes all core Signal functionality. Optional subsystems are
gated behind build tags to avoid pulling in unnecessary dependencies.

| Build Tag | Package                  | Description                          |
|-----------|--------------------------|--------------------------------------|
| `fido2`   | `pkg/fido2/`             | WebAuthn/FIDO2 credential management |
| `smtp`    | `pkg/verification/smtp/` | SMTP-based SMS verification          |
| `signal`  | -                        | QuicBaaS Signal integration          |

```bash
# Base build (no extensions)
make build

# FIDO2 support
make build-fido2

# SMTP verification
make build-smtp

# All extensions
make build-all
```

---

## Package Map

```
cmd/
  signald/                Server daemon (cobra commands: start, version)
  signalctl/              CLI control tool

pkg/
  accounts/               Account lifecycle management
  api/
    grpc/                 gRPC services and interceptors
    rest/                 REST HTTP/2 handlers
    websocket/            WebSocket connection management
  auth/                   Authentication and authorization
  backup/                 Backup management
  badges/                 Badge management
  calling/                Voice/video calling support
  captcha/                Captcha verification
  certificates/           Delivery certificates
  config/                 YAML configuration loading
    secrets/              Secret URI resolution (kms://, ${ENV})
  devices/                Multi-device management
  directory/              Contact discovery
  errors/                 Shared typed errors
  fido2/                  WebAuthn/FIDO2 (build-tagged)
  groups/                 Group management
  keys/                   Pre-key bundle management
  keytransparency/        Key transparency
  limits/                 Rate limiting
  messages/               Message routing and storage
  metrics/                Prometheus metrics
  profiles/               Profile management
  push/                   Push notification dispatch (APN, FCM)
  registration/           Account registration
  securestorage/          Secure storage
  securevaluerecovery/    SVR protocol
  spam/                   Spam detection
  stickers/               Sticker pack management
  store/                  KVClient interface and implementations
  storage/                Storage adapter layer
  subscriptions/          Payment subscriptions
  usernames/              Username management
  verification/           Phone number verification
    smtp/                 SMTP transport (build-tagged)
  websocket/              WebSocket protocol handling

test/
  integration/            Integration tests
  performance/            Benchmark documentation
  tls/                    TLS certificate test files
  signal-cli/             Signal-cli test harness
```

---

## Configuration

The server is configured via YAML files. Secret values support `kms://` URIs
and `${ENV_VAR}` expansion through the `pkg/config/secrets/` subsystem. See
[configuration/reference.md](../configuration/reference.md) for the full reference.
