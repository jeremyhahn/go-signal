# Secrets Management

The server resolves sensitive configuration values at startup so that secrets never need to appear as plaintext in YAML files. Three resolution mechanisms are supported, each suited to a different deployment environment.

Source: `pkg/config/secrets/`

## Resolution Mechanisms

### KMS URI (`kms://`)

For production deployments. A `kms://` URI references a secret stored in an external key management system. You must register a `SecretResolver` implementation for the `kms` scheme before config processing runs.

```yaml
storage:
  postgres:
    password: "kms://secrets/db-password"
```

The URI format is `kms://<path>` where the path is opaque to the framework and interpreted by the registered resolver. This lets you plug in AWS KMS, HashiCorp Vault, GCP Secret Manager, or any other backend by implementing a single interface.

### Environment Variables (`${VAR}`)

For container and CI/CD deployments. Wrapping a field value in `${...}` tells the processor to read the named environment variable.

```yaml
cdn:
  accessKey: "${AWS_ACCESS_KEY_ID}"
  secretKey: "${AWS_SECRET_ACCESS_KEY}"
```

The entire field value must be a single `${VAR}` reference. Inline interpolation (e.g., `prefix-${VAR}-suffix`) is not supported. If the referenced variable is not set in the process environment, resolution fails with an `EnvVarNotSetError`.

### Auto-Generation (sentinel values)

For development and testing. The following sentinel values trigger automatic generation of a cryptographically random 32-byte hex string (64 characters) via `crypto/rand`:

- `"auto"`
- `"changeme"`
- `"placeholder"`

```yaml
turn:
  secret: "auto"
zkConfig:
  serverSecret: "changeme"
```

Generated values are cached in memory for the lifetime of the process. The same sentinel in different fields produces different secrets, but reprocessing the same field returns the same value. These secrets are **not persisted** anywhere. Every process restart generates new values.

This mechanism exists so you can run a development server without creating real secrets. Do not use sentinel values in production.

---

## Resolution Pipeline

The `ConfigProcessor` resolves secrets by walking the `Config` struct using reflection.

1. For each exported string field in the struct tree, the processor checks the `ResolverRegistry` for a resolver whose scheme matches the field value.
2. If a match is found, the resolver's `Resolve` method is called and the field is replaced in place.
3. If no scheme matches, the field is left unchanged.
4. The walk is recursive through nested structs and pointer fields. Nil pointers are skipped.

```go
registry := secrets.NewResolverRegistry()
registry.Register(myKMSResolver)

processor := secrets.NewConfigProcessor(registry)
err := processor.Process(ctx, &config)
```

The processor requires a pointer to a struct. Passing anything else returns a `ProcessingError`.

---

## Interfaces

### SecretResolver

Any secret backend implements this two-method interface:

```go
type SecretResolver interface {
    // Scheme returns the URI scheme this resolver handles (e.g., "kms", "env").
    Scheme() string

    // Resolve resolves the given URI to its plaintext value.
    Resolve(ctx context.Context, uri string) (string, error)
}
```

### ResolverRegistry

A map-based dispatcher keyed by URI scheme. Resolvers are registered at startup and looked up during config processing.

```go
type ResolverRegistry struct {
    resolvers map[string]SecretResolver
}
```

Key methods:

| Method | Description |
|---|---|
| `NewResolverRegistry()` | Creates an empty registry |
| `Register(resolver)` | Adds a resolver by its scheme; replaces if already registered |
| `Resolve(ctx, value)` | Parses the scheme from the value and delegates to the matching resolver |
| `HasResolver(scheme)` | Reports whether a resolver is registered for the given scheme |

If `Resolve` is called with a value containing a `://` scheme that has no registered resolver, it returns a `ResolverNotFoundError`. Values without a `://` separator pass through unchanged.

---

## Built-in Resolvers

### EnvResolver

Handles `${VAR}` references. Uses `os.LookupEnv` to read the variable. Returns `EnvVarNotSetError` if the variable is not present in the environment.

```go
resolver := secrets.NewEnvResolver()
// resolver.Scheme() returns "env"
```

The `EnvResolver` is invoked for values matching the `${...}` pattern rather than the `env://` URI scheme. The `ConfigProcessor` detects the `${...}` syntax and routes to this resolver directly.

### AutoGenResolver

Handles sentinel values (`"auto"`, `"changeme"`, `"placeholder"`). Generates random secrets using `crypto/rand` and caches them in a `map[string]string` protected by `sync.RWMutex` with double-checked locking.

```go
resolver := secrets.NewAutoGenResolver(32) // 32 bytes = 64 hex chars
// resolver.Scheme() returns "autogen"
```

The byte length parameter controls the size of the generated secret. If zero or negative, it defaults to 32.

---

## Error Types

All errors are typed structs in `pkg/config/secrets/errors.go`.

| Error Type | When | Fields |
|---|---|---|
| `ResolverNotFoundError` | A URI scheme has no registered resolver | `Scheme` |
| `ResolutionError` | A resolver returned an error | `URI`, `Cause` |
| `ProcessingError` | Failure during struct walking/resolution | `Field`, `Cause` |
| `InvalidURIError` | A URI is malformed | `URI`, `Message` |
| `EnvVarNotSetError` | A referenced environment variable is not set | `VarName` |

`ResolutionError` and `ProcessingError` implement `Unwrap()` for use with `errors.As` and `errors.Is`.

---

## Environment-Specific Examples

### Development

Memory backend, auto-generated secrets, stub verification. No external dependencies required.

```yaml
server:
  httpPort: 8080

storage:
  backend: "memory"

cache:
  backend: "memory"

verification:
  transport: "stub"

turn:
  secret: "auto"

zkConfig:
  serverSecret: "auto"

payments:
  stripe:
    apiKey: "placeholder"
    webhookSecret: "placeholder"
```

### Production with KMS

All secrets resolved through an external key management system. Requires a registered `kms` resolver.

```yaml
server:
  httpPort: 8080
  grpcPort: 9090
  tlsCertFile: /etc/signal/tls/cert.pem
  tlsKeyFile: /etc/signal/tls/key.pem

storage:
  backend: "postgres"
  postgres:
    host: "db.internal"
    port: 5432
    database: "signal"
    user: "signal"
    password: "kms://secrets/db-password"
    sslMode: "verify-full"

cache:
  backend: "redis"
  redis:
    url: "redis://cache.internal:6379"
    password: "kms://secrets/redis-password"

turn:
  secret: "kms://secrets/turn-secret"

zkConfig:
  enabled: true
  serverSecret: "kms://secrets/zk-server-secret"

push:
  apn:
    privateKey: "kms://secrets/apn-private-key"
  fcm:
    credentials: "kms://secrets/fcm-credentials"

payments:
  stripe:
    apiKey: "kms://secrets/stripe-api-key"
    webhookSecret: "kms://secrets/stripe-webhook"

verification:
  transport: "smtp"
  smtp:
    host: "smtp.internal"
    port: 587
    password: "kms://secrets/smtp-password"
    fromAddress: "verify@example.com"
    useTLS: true
```

### Production with Environment Variables

All secrets injected via environment variables. Common in Kubernetes or Docker Compose deployments.

```yaml
server:
  httpPort: 8080
  grpcPort: 9090
  tlsCertFile: /etc/signal/tls/cert.pem
  tlsKeyFile: /etc/signal/tls/key.pem

storage:
  backend: "postgres"
  postgres:
    host: "${POSTGRES_HOST}"
    port: 5432
    database: "signal"
    user: "${POSTGRES_USER}"
    password: "${POSTGRES_PASSWORD}"
    sslMode: "verify-full"

cache:
  backend: "redis"
  redis:
    url: "${REDIS_URL}"
    password: "${REDIS_PASSWORD}"

turn:
  secret: "${TURN_SECRET}"

zkConfig:
  enabled: true
  serverSecret: "${ZK_SERVER_SECRET}"

cdn:
  bucket: "signal-attachments"
  region: "us-east-1"
  accessKey: "${AWS_ACCESS_KEY_ID}"
  secretKey: "${AWS_SECRET_ACCESS_KEY}"

verification:
  transport: "smtp"
  smtp:
    host: "${SMTP_HOST}"
    port: 587
    password: "${SMTP_PASSWORD}"
    fromAddress: "verify@example.com"
    useTLS: true
```

Set the variables before starting the server:

```bash
export POSTGRES_HOST=db.internal
export POSTGRES_USER=signal
export POSTGRES_PASSWORD=hunter2
export REDIS_URL=redis://cache.internal:6379
export REDIS_PASSWORD=redispass
export TURN_SECRET=$(openssl rand -hex 32)
export ZK_SERVER_SECRET=$(openssl rand -hex 32)
export SMTP_HOST=smtp.internal
export SMTP_PASSWORD=smtppass
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...

signald start --config /etc/signal/config.yaml
```
