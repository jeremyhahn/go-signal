# gRPC API

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of the go-signal gRPC server in `pkg/api/grpc`.

go-signal serves the `org.signal.chat.*` services of Java Signal-Server plus the external-infrastructure services (RegistrationService, KeyTransparencyQueryService, DirectoryService). The `.proto` files live under `pkg/api/grpc/proto/`.

Generated Go code lands under `pkg/api/grpc/genproto/`. Regenerate with:

```sh
make proto
```

## Startup

`cmd/signald/start.go` starts the gRPC server only when `server.grpcPort` is non-zero, bound to `server.host:server.grpcPort`. `grpc.New` (`pkg/api/grpc/server.go`) builds a plain `grpc.NewServer` with one unary interceptor and no transport credentials, so the listener is plaintext; `server.tlsCertFile` and `server.tlsKeyFile` are not applied to it. There are no stream interceptors.

## Services

All of the services below are registered. Most have no method bodies yet: they embed the generated `Unimplemented<Name>Server`, so an RPC returns `codes.Unimplemented` after the interceptor has run. The implemented RPCs are listed under [Implementation status](#implementation-status).

### Authenticated

These require Basic credentials in the `authorization` metadata. See [authentication.md](../auth/authentication.md) for the credential format.

| Proto | Go package |
|---|---|
| `org.signal.chat.account.Accounts` | `pkg/api/grpc/genproto/account` |
| `org.signal.chat.messages.Messages` | `pkg/api/grpc/genproto/messages` |
| `org.signal.chat.keys.Keys` | `pkg/api/grpc/genproto/keys` |
| `org.signal.chat.profile.Profile` | `pkg/api/grpc/genproto/profile` |
| `org.signal.chat.device.Devices` | `pkg/api/grpc/genproto/device` |
| `org.signal.chat.backup.Backups` | `pkg/api/grpc/genproto/backups` |
| `org.signal.chat.calling.Calling` | `pkg/api/grpc/genproto/calling` |
| `org.signal.chat.calling.quality.CallQuality` | `pkg/api/grpc/genproto/call_quality` |
| `org.signal.chat.credentials.ExternalServiceCredentials` | `pkg/api/grpc/genproto/credentials` |
| `org.signal.chat.payments.Payments` | `pkg/api/grpc/genproto/payments` (permanently `Unimplemented`; see [ADR-0003](../architecture/decisions/0003-skip-payments.md)) |

Any method whose full name matches neither list below goes through the authenticated interceptor.

### Anonymous

These reject requests carrying `authorization` metadata. They serve anonymous and sealed-sender callers.

| Proto | Go package |
|---|---|
| `org.signal.chat.account.AccountsAnonymous` | `pkg/api/grpc/genproto/account` |
| `org.signal.chat.messages.MessagesAnonymous` | `pkg/api/grpc/genproto/messages` |
| `org.signal.chat.keys.KeysAnonymous` | `pkg/api/grpc/genproto/keys` |
| `org.signal.chat.profile.ProfileAnonymous` | `pkg/api/grpc/genproto/profile` |
| `org.signal.chat.backup.BackupsAnonymous` | `pkg/api/grpc/genproto/backups` |
| `org.signal.chat.credentials.ExternalServiceCredentialsAnonymous` | `pkg/api/grpc/genproto/credentials` |

### External-infrastructure services

These carry their own authentication model and bypass both interceptors.

| Proto | Go package | Where it runs |
|---|---|---|
| `org.signal.registration.rpc.RegistrationService` | `pkg/api/grpc/genproto/registrationservice` | `cmd/registration-service` only; signald does not register it |
| `kt_query.KeyTransparencyQueryService` | `pkg/api/grpc/genproto/keytransparencyservice` | `cmd/key-transparency`; signald registers an `Unimplemented` stub |
| `org.signal.directory.DirectoryService` | `pkg/api/grpc/genproto/directory` | signald, consumed by `cmd/cdsi`; registered when the directory account source is non-nil, which `cmd/signald` always supplies |

See [ADR-0002](../architecture/decisions/0002-external-services-as-separate-binaries.md).

## Interceptor chain

One unary interceptor, `routingInterceptor` in `pkg/api/grpc/server.go`, inspects `UnaryServerInfo.FullMethod` and picks a flavour. The service lists are the hard-coded `anonymousServicePrefixes` and `externalInfraPrefixes`.

1. **Anonymous**: the six `...Anonymous` services. `interceptors.AnonymousUnary` rejects any request with `authorization` metadata using `codes.PermissionDenied`.
2. **Pass-through**: the three external-infrastructure services above; the handler runs directly.
3. **Authenticated**: everything else. `interceptors.AuthenticatedUnary` (`pkg/api/grpc/interceptors/auth.go`) parses Basic credentials from metadata, verifies the `AuthTokenHash` of the addressed device (`uuid.deviceId`, defaulting to the primary device), and stores the `*accounts.Account` and device ID in the context under `interceptors.AccountContextKey` and `interceptors.DeviceContextKey`. Read them with `interceptors.AccountFromContext` and `interceptors.DeviceIDFromContext`. It mirrors the REST middleware in `pkg/api/rest/middleware.go`, including timing equalisation on failure paths.

## Implementation status

| Service | State |
|---|---|
| `Backups`, `BackupsAnonymous` | Implemented in `pkg/api/grpc/services/backups.go` |
| `MessagesAnonymous.SendMultiRecipientMessage` | Implemented in `pkg/api/grpc/services/services.go`; the `ephemeral` flag is ignored |
| `DirectoryService` | Implemented in `pkg/api/grpc/services/directory` |
| `Payments` | `Unimplemented` by decision |
| All other RPCs of the services above | `Unimplemented` |

## Client usage

```go
conn, err := grpc.NewClient("signald.internal:9090",
    grpc.WithTransportCredentials(insecure.NewCredentials()))
if err != nil { … }
defer conn.Close()

client := accountpb.NewAccountsClient(conn)

ctx := metadata.AppendToOutgoingContext(context.Background(),
    "authorization", "Basic "+base64.StdEncoding.EncodeToString(
        []byte(accountUUID+":"+password)))

resp, err := client.GetAccountIdentity(ctx, &accountpb.GetAccountIdentityRequest{})
```

The port is `server.grpcPort`. Because the server installs no transport credentials, the client must use insecure credentials unless TLS is terminated in front of it.
