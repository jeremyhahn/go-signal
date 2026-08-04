# gRPC API

go-signal exposes the same gRPC surface as Java Signal-Server's
`org.signal.chat.*` services plus the external-infrastructure
services (RegistrationService, KeyTransparencyQueryService). The
underlying `.proto` files are copied verbatim from the Java repo and
live under `pkg/api/grpc/proto/`.

Generated Go code lands under `pkg/api/grpc/genproto/`. Regenerate
with:

```sh
make proto
```

## Services

Everything listed below is **registered and reachable** in Phase 1.
Method bodies return `codes.Unimplemented` until the corresponding
Phase 2 work lands — the interceptor chain, transport, and routing
are exercised regardless.

### Authenticated (AUTH_ONLY_AUTHENTICATED)

These require HTTP Basic credentials in the `authorization` gRPC
metadata. See [auth.md](../auth/authentication.md) for credential
format.

| Proto                                          | Go package                                       |
|------------------------------------------------|--------------------------------------------------|
| `org.signal.chat.account.Accounts`             | `pkg/api/grpc/genproto/account`                  |
| `org.signal.chat.messages.Messages`            | `pkg/api/grpc/genproto/messages`                 |
| `org.signal.chat.keys.Keys`                    | `pkg/api/grpc/genproto/keys`                     |
| `org.signal.chat.profile.Profile`              | `pkg/api/grpc/genproto/profile`                  |
| `org.signal.chat.device.Devices`               | `pkg/api/grpc/genproto/device`                   |
| `org.signal.chat.backup.Backups`               | `pkg/api/grpc/genproto/backups`                  |
| `org.signal.chat.calling.Calling`              | `pkg/api/grpc/genproto/calling`                  |
| `org.signal.chat.calling.quality.CallQuality`  | `pkg/api/grpc/genproto/call_quality`             |
| `org.signal.chat.credentials.ExternalServiceCredentials` | `pkg/api/grpc/genproto/credentials`    |
| `org.signal.chat.payments.Payments`            | `pkg/api/grpc/genproto/payments` (permanently `Unimplemented`; see [ADR-0003](../architecture/decisions/0003-skip-payments.md)) |

### Anonymous (AUTH_ONLY_ANONYMOUS)

These *reject* requests carrying `authorization` metadata. They are
reached by anonymous or sealed-sender callers.

| Proto                                                      | Go package                                        |
|------------------------------------------------------------|---------------------------------------------------|
| `org.signal.chat.account.AccountsAnonymous`                | `pkg/api/grpc/genproto/account`                   |
| `org.signal.chat.messages.MessagesAnonymous`               | `pkg/api/grpc/genproto/messages`                  |
| `org.signal.chat.keys.KeysAnonymous`                       | `pkg/api/grpc/genproto/keys`                      |
| `org.signal.chat.profile.ProfileAnonymous`                 | `pkg/api/grpc/genproto/profile`                   |
| `org.signal.chat.backup.BackupsAnonymous`                  | `pkg/api/grpc/genproto/backups`                   |
| `org.signal.chat.credentials.ExternalServiceCredentialsAnonymous` | `pkg/api/grpc/genproto/credentials`        |

### External-infrastructure services

These will migrate to their own binaries in Phase 4 (see
[ADR-0002](../architecture/decisions/0002-external-services-as-separate-binaries.md)).
Until then they live inside signald as stubs.

| Proto                                              | Go package                                                 |
|----------------------------------------------------|------------------------------------------------------------|
| `org.signal.registration.rpc.RegistrationService`  | `pkg/api/grpc/genproto/registrationservice`                |
| `kt_query.KeyTransparencyQueryService`             | `pkg/api/grpc/genproto/keytransparencyservice`             |

## Interceptor chain

A single routing interceptor on the gRPC server inspects
`UnaryServerInfo.FullMethod` and dispatches to one of three
flavours:

1. **Authenticated** — for every service in the first table above.
   Parses Basic credentials from metadata, verifies the `AuthTokenHash`
   of the *addressed* device (`uuid.deviceId`, defaulting to the primary
   device), and attaches both the `*accounts.Account` and the
   authenticated device ID to the context via
   `interceptors.AccountContextKey` / `interceptors.DeviceContextKey`
   (read with `AccountFromContext` / `DeviceIDFromContext`). Mirrors the
   REST middleware in `pkg/api/rest/middleware.go`, including its
   timing-equalisation on failure paths.
2. **Anonymous** — rejects any request carrying
   `authorization` metadata with `codes.PermissionDenied`.
3. **Pass-through** — for the external-infrastructure services,
   which carry their own auth (mTLS + HMAC tokens) enforced inside
   the service body rather than at the transport edge.

See `pkg/api/grpc/server.go` `routingInterceptor` for the
implementation.

## Client usage

```go
conn, err := grpc.NewClient("signald.internal:8080",
    grpc.WithTransportCredentials(insecure.NewCredentials()))
if err != nil { … }
defer conn.Close()

client := accountpb.NewAccountsClient(conn)

ctx := metadata.AppendToOutgoingContext(context.Background(),
    "authorization", "Basic "+base64.StdEncoding.EncodeToString(
        []byte(accountUUID+":"+password)))

resp, err := client.GetAccountIdentity(ctx, &accountpb.GetAccountIdentityRequest{})
```

## Phase 2 roadmap

Method bodies are replaced by real delegation to `pkg/service`
interfaces in the order:

1. `Accounts.GetAccountIdentity` / `Accounts.SetAccountAttributes`
2. `Keys.*` (PQ-key upload + claim).
3. `Messages.SendMessage` / `Messages.SendSyncMessage`.
4. `Profile.SetProfile` / `Profile.GetProfile`.
5. `Devices.*` (link/unlink).
6. `Backups.*` (media + message archive).

Each replacement is a single-file change in `pkg/api/grpc/services/`
that replaces the `Unimplemented<Name>Server` embed with a custom
method set.
