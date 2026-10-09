# Secrets Management

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of the go-signal `pkg/config/secrets` package and how configuration secrets are held.

Source: `pkg/config/secrets/`

## What the daemon does today

Secret-bearing config fields are typed `*secrets.SecureString` (for example `storage.postgres.password`, `cache.redis.password`, `turn.cloudflare.apiToken`, `zkConfig.serverSecret`). `SecureString.UnmarshalYAML` (`pkg/config/secrets/secure.go`) seals the YAML text into protected memory as it is decoded, and `Config.Destroy` (`pkg/config/config.go`) wipes every such field at shutdown.

The value is taken **literally**. Nothing under `cmd/` or in `config.Load` constructs a `ResolverRegistry` or calls `ConfigProcessor.Process`, so in the daemon a `kms://...`, `${VAR}`, or `auto` value is used as the secret text itself. Inject secrets by writing them into the file the daemon reads (for example a mounted secret file); do not rely on `${VAR}` expansion in the YAML.

The resolution framework below is a library with tests. Embedding applications can wire it in before they use the config.

## Resolution framework

### SecretResolver

```go
type SecretResolver interface {
    // Scheme returns the URI scheme this resolver handles.
    Scheme() string

    // Resolve resolves the given URI to its plaintext value in a SecureString.
    // The caller owns the result and must call Destroy.
    Resolve(ctx context.Context, uri string) (*SecureString, error)
}
```

### ResolverRegistry

A map keyed by URI scheme (`pkg/config/secrets/resolver.go`).

| Method | Description |
|---|---|
| `NewResolverRegistry()` | Creates an empty registry |
| `Register(resolver)` | Adds a resolver under `resolver.Scheme()`; replaces an existing one |
| `Resolve(ctx, value)` | Empty value: an empty optional `SecureString`. Value with `scheme://` and a registered resolver: that resolver's result, wrapped in `*ResolutionError` on failure. Unregistered scheme: `*ResolverNotFoundError`. Value without `://`: wrapped unchanged in a `SecureString` |
| `HasResolver(scheme)` | Reports whether a resolver is registered for the scheme |

A `kms://<path>` value therefore resolves only if the application registers a resolver whose `Scheme()` is `kms`. The package ships no KMS resolver.

### ConfigProcessor

`NewConfigProcessor(registry).Process(ctx, &cfg)` walks a struct by reflection (`processor.go`):

1. Every settable exported `string` and `*SecureString` field that is non-empty is passed to `registry.Resolve`.
2. If the result differs, the field is replaced in place (a `*SecureString` field gets the new `SecureString`, and the old one is destroyed).
3. Nested structs and non-nil pointers are walked; nil pointers are skipped.
4. A failure is returned as `*ProcessingError` naming the field path.

`cfg` must be a pointer to a struct; anything else returns a `*ProcessingError`.

Only `scheme://` values reach a resolver. The processor does not detect `${VAR}` or sentinel values.

### CachingResolver

`NewCachingResolver(r, ttl)` (`caching.go`) wraps a resolver with a TTL cache so that `kms://` secrets pick up rotations; `Invalidate(uri)` drops one entry.

## Built-in resolvers

### EnvResolver

`NewEnvResolver()` resolves a value of the form `${VAR}` (surrounding whitespace is trimmed) from the process environment with `os.LookupEnv`. An unset variable returns `*EnvVarNotSetError`; an exported empty variable is accepted. `IsEnvVar(value)` reports whether a value has that form. `Scheme()` returns `"env"`, but registering it under that scheme does not make `${VAR}` values reach it, because the registry only dispatches `scheme://` values. Call `Resolve` directly.

### AutoGenResolver

`NewAutoGenResolver(byteLength)` replaces the sentinels `"auto"`, `"changeme"` and `"placeholder"` (`IsSentinel`) with a `crypto/rand` hex string of `2 × byteLength` characters (a `byteLength` of zero or less becomes 32, so 64 characters). The value is cached per sentinel for the life of the resolver, so repeated calls return the same secret and different sentinels differ. Nothing is persisted. `Scheme()` returns `"autogen"`; as with `EnvResolver`, call `Resolve` directly. Do not use sentinels in production.

## Error types

Typed errors in `pkg/config/secrets/errors.go`:

| Error Type | When | Fields |
|---|---|---|
| `ResolverNotFoundError` | A URI scheme has no registered resolver | `Scheme` |
| `ResolutionError` | A resolver returned an error | `URI`, `Cause` |
| `ProcessingError` | Failure while walking the struct | `Field`, `Cause` |
| `InvalidURIError` | A URI is malformed | `URI`, `Message` |
| `EnvVarNotSetError` | A referenced environment variable is not set | `VarName` |
| `EmptySecretError` | `NewSecureString` was given an empty value | none |
| `UnavailableSecretError` | A secret could not be read back from protected memory: unset, destroyed, or the enclave would not open | `Cause` |
| `SealError` | The protected-memory allocation could not be obtained | `Cause` |
| `AbsentSecretError` | A secret was never configured (distinct from one that is no longer readable) | none |

`ResolutionError`, `ProcessingError`, `UnavailableSecretError` and `SealError` implement `Unwrap()`.

## Production

`mode: production` makes `config.Load` refuse to start with development secrets. Among other checks, `callingZkConfig.serverSecret` must not be the well-known development value, `cdn.accessKey` and `cdn.secretKey` must not be the development placeholders, and `zkConfig` must be enabled with a non-empty `serverSecret` (`validateProduction`, `pkg/config/config.go`). See [reference.md](reference.md).
