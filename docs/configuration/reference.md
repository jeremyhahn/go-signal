# Configuration Reference

The go-signal server reads a single YAML configuration file at startup. Every runtime option is controlled through this file.

## Loading

Pass the config path when starting the daemon:

```bash
signald start --config /path/to/config.yaml
```

The load process has three steps:

1. **Parse YAML** - Read the file and unmarshal into the `Config` struct.
2. **Resolve secret URIs** - Walk all string fields and resolve `kms://`, `${VAR}`, and sentinel values through the `ConfigProcessor`. See [secrets.md](../configuration/secrets.md) for details.
3. **Validate** - Check required fields and apply defaults.

If any step fails, the server exits with a typed error:

| Error Type | Trigger |
|---|---|
| `ConfigLoadError` | File cannot be read (missing, permission denied, etc.) |
| `ConfigParseError` | YAML is malformed or cannot be unmarshaled |
| `ConfigValidationError` | A required field is missing or a value is out of range |

Source: `pkg/config/config.go`

---

## server

HTTP/2 and gRPC listener settings.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Host | `host` | string | No | `""` (all interfaces) | Bind address for listeners |
| HTTPPort | `httpPort` | int | * | - | Port for the HTTP/2 REST API |
| GRPCPort | `grpcPort` | int | * | - | Port for the gRPC API |
| TLSCertFile | `tlsCertFile` | string | No | - | Path to TLS certificate PEM file |
| TLSKeyFile | `tlsKeyFile` | string | No | - | Path to TLS private key PEM file |
| MaxDevices | `maxDevices` | int | No | `6` | Maximum linked devices per account |

\* At least one of `httpPort` or `grpcPort` must be non-zero. Both can be set to run REST and gRPC simultaneously.

```yaml
server:
  host: "0.0.0.0"
  httpPort: 8080
  grpcPort: 9090
  tlsCertFile: /etc/signal/tls/cert.pem
  tlsKeyFile: /etc/signal/tls/key.pem
  maxDevices: 6
```

---

## storage

Persistent backend selection. The `backend` field determines which nested section is used.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Backend | `backend` | string | No | `"memory"` | One of: `"memory"` (default), `"file"`, `"postgres"`, `"qrdb"` |

The `signald` daemon wires these backends in `cmd/signald` (see the storage-backend
switch): `"memory"` (ephemeral, the default), `"file"` (KV-backed, persists under
`storage.file.dataDir`), `"postgres"` (the `storage.postgres` section), and `"qrdb"`
(the production KV backend; currently an in-process transport with no dedicated config
section). An unrecognized value falls back to `"memory"`.

### storage.file

Used when `backend: "file"`.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| DataDir | `dataDir` | string | No | `"data"` | Root directory for the file-system KV store |

```yaml
storage:
  backend: "file"
  file:
    dataDir: "/var/lib/signald/data"
```

### storage.dynamodb

DynamoDB configuration is declared in the config schema but is **not wired into the
`signald` daemon's backend switch** in the current build (selecting `"dynamodb"` falls
back to `"memory"`). The fields below are retained for forward compatibility.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Region | `region` | string | No | - | AWS region (e.g., `us-east-1`) |
| Endpoint | `endpoint` | string | No | - | Custom endpoint URL (for LocalStack, etc.) |
| AccountsTable | `accountsTable` | string | No | - | Table name for accounts |
| MessagesTable | `messagesTable` | string | No | - | Table name for messages |
| KeysTable | `keysTable` | string | No | - | Table name for pre-keys |
| ProfilesTable | `profilesTable` | string | No | - | Table name for profiles |
| PendingAccounts | `pendingAccountsTable` | string | No | - | Table name for pending accounts |

```yaml
storage:
  backend: "dynamodb"
  dynamodb:
    region: "us-east-1"
    endpoint: "http://localhost:4566"
    accountsTable: "signal-accounts"
    messagesTable: "signal-messages"
    keysTable: "signal-keys"
    profilesTable: "signal-profiles"
    pendingAccountsTable: "signal-pending"
```

### storage.postgres

Used when `backend: "postgres"`.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Host | `host` | string | No | - | PostgreSQL host |
| Port | `port` | int | No | - | PostgreSQL port |
| Database | `database` | string | No | - | Database name |
| User | `user` | string | No | - | Database user |
| Password | `password` | string | No | - | Database password (supports secret URIs) |
| SSLMode | `sslMode` | string | No | - | SSL mode: `"disable"`, `"require"`, `"verify-full"`, etc. |

The `password` field supports secret resolution. You can use `kms://` URIs, `${ENV_VAR}` references, or sentinel values. See [secrets.md](../configuration/secrets.md).

```yaml
storage:
  backend: "postgres"
  postgres:
    host: "db.internal"
    port: 5432
    database: "signal"
    user: "signal"
    password: "kms://secrets/db-password"
    sslMode: "verify-full"
```

---

## cache

Optional caching layer.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Backend | `backend` | string | No | - | One of: `"redis"`, `"memory"` |

### cache.redis

Used when `backend: "redis"`.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| URL | `url` | string | No | - | Redis connection URL |
| Password | `password` | string | No | - | Redis password (supports secret URIs) |
| DB | `db` | int | No | `0` | Redis database number |

```yaml
cache:
  backend: "redis"
  redis:
    url: "redis://cache.internal:6379"
    password: "${REDIS_PASSWORD}"
    db: 0
```

---

## push

Push notification service configuration.

### push.apn

Apple Push Notification service settings.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| TeamID | `teamId` | string | No | - | Apple Developer team ID |
| KeyID | `keyId` | string | No | - | APNs auth key ID |
| BundleID | `bundleId` | string | No | - | iOS app bundle identifier |
| PrivateKey | `privateKey` | string | No | - | APNs auth key (supports secret URIs) |
| Sandbox | `sandbox` | bool | No | `false` | Use APNs sandbox environment |

### push.fcm

Firebase Cloud Messaging settings.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Credentials | `credentials` | string | No | - | FCM service account credentials JSON (supports secret URIs) |

```yaml
push:
  apn:
    teamId: "ABCDE12345"
    keyId: "KEY123"
    bundleId: "org.signal.ios"
    privateKey: "kms://secrets/apn-key"
    sandbox: false
  fcm:
    credentials: "kms://secrets/fcm-creds"
```

---

## cdn

Attachment and media storage.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Bucket | `bucket` | string | No | - | S3-compatible bucket name |
| Region | `region` | string | No | - | Bucket region |
| AccessKey | `accessKey` | string | No | - | Access key (supports secret URIs) |
| SecretKey | `secretKey` | string | No | - | Secret key (supports secret URIs) |

```yaml
cdn:
  bucket: "signal-attachments"
  region: "us-east-1"
  accessKey: "${AWS_ACCESS_KEY_ID}"
  secretKey: "${AWS_SECRET_ACCESS_KEY}"
```

---

## limits

Token-bucket rate limiting. Each subsection configures a separate limiter. Tokens refill at `leakRatePerMin` tokens per minute up to `bucketSize`.

| Section | YAML Key | Description |
|---|---|---|
| Messages | `messages` | Rate limit on message sends |
| PreKeys | `preKeys` | Rate limit on pre-key uploads |
| Attachment | `attachment` | Rate limit on attachment uploads |
| Profile | `profile` | Rate limit on profile updates |

Each section has the same fields:

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| BucketSize | `bucketSize` | int | No | - | Maximum burst size |
| LeakRatePerMin | `leakRatePerMin` | int | No | - | Token refill rate per minute |

```yaml
limits:
  messages:
    bucketSize: 256
    leakRatePerMin: 60
  preKeys:
    bucketSize: 10
    leakRatePerMin: 5
  attachment:
    bucketSize: 25
    leakRatePerMin: 10
  profile:
    bucketSize: 10
    leakRatePerMin: 5
```

---

## turn

TURN relay server credentials. The server generates time-limited TURN credentials using the shared secret.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Secret | `secret` | string | No | - | HMAC shared secret (supports secret URIs) |
| URIs | `uris` | []string | No | - | TURN server URIs |

```yaml
turn:
  secret: "kms://secrets/turn-secret"
  uris:
    - "turn:turn.example.com:3478"
    - "turns:turn.example.com:5349"
```

---

## zkConfig

Zero-knowledge proof configuration for anonymous credentials.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Enabled | `enabled` | bool | No | `false` | Enable ZK credential support |
| ServerSecret | `serverSecret` | string | No | - | ZK server secret key (supports secret URIs) |

```yaml
zkConfig:
  enabled: true
  serverSecret: "kms://secrets/zk-server-secret"
```

---

## payments

Payment processing configuration.

### payments.stripe

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| APIKey | `apiKey` | string | No | - | Stripe API key (supports secret URIs) |
| WebhookSecret | `webhookSecret` | string | No | - | Stripe webhook signing secret (supports secret URIs) |

```yaml
payments:
  stripe:
    apiKey: "kms://secrets/stripe-api-key"
    webhookSecret: "kms://secrets/stripe-webhook-secret"
```

---

## directory

Contact discovery settings.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Enabled | `enabled` | bool | No | `false` | Enable the contact discovery directory |

```yaml
directory:
  enabled: true
```

---

## storageService

Encrypted contact/settings sync storage. signald can either run this in-process (monolithic deployments) or talk to a standalone `storage-service` binary. The mode is selected by `remoteUrl`: when it is **empty**, signald enables the embedded storage-service and serves the `/storage/...` routes itself; when it is set, signald only acts as a privileged admin client (DELETE-on-account-deletion) and the in-process routes fall back to a `204` stub.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| HTTPListen | `httpListen` | string | No | `0.0.0.0:8096` | Bind address for the standalone `storage-service` binary |
| SharedSecret | `sharedSecret` | string | No* | - | HMAC secret shared between signald and storage-service for credential derivation (supports secret URIs) |
| RemoteURL | `remoteUrl` | string | No | `""` (embedded) | storage-service admin endpoint. Empty enables the in-process storage-service |
| RemoteInsecure | `remoteInsecure` | bool | No | `false` | Permit a plaintext HTTP channel to storage-service (development only; production requires TLS 1.3) |

\* Not enforced at config-load time, but required in practice: it is the HMAC key that signald uses to mint `/v1/storage/auth` credentials and that storage-service uses to verify them.

```yaml
# Monolithic: embedded storage-service (default)
storageService:
  sharedSecret: "kms://secrets/storage-shared-secret"

# Distributed: external storage-service binary
storageService:
  sharedSecret: "kms://secrets/storage-shared-secret"
  remoteUrl: "https://storage-service.internal:8096"
```

Source: `pkg/config/config.go` (`StorageServiceConfig`)

---

## verification

Phone number verification settings.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| CodeLength | `codeLength` | int | No | `6` | Number of digits in verification codes |
| CodeTTLSeconds | `codeTTLSeconds` | int | No | `300` | Seconds before a code expires |
| MaxAttempts | `maxAttempts` | int | No | `3` | Maximum code submission attempts per session |
| Transport | `transport` | string | No | `"stub"` | Delivery transport: `"smtp"` or `"stub"` |

The `stub` transport logs codes to stdout and is intended for development only.

Source: `pkg/config/config_verification.go`

### verification.smtp

Used when `transport: "smtp"`. Requires the `smtp` build tag.

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Host | `host` | string | No | - | SMTP server hostname |
| Port | `port` | int | No | - | SMTP server port |
| Username | `username` | string | No | - | SMTP auth username |
| Password | `password` | string | No | - | SMTP auth password (supports secret URIs) |
| FromAddress | `fromAddress` | string | No | - | Sender email address |
| UseTLS | `useTLS` | bool | No | `false` | Enable STARTTLS |
| DefaultCarrier | `defaultCarrier` | string | No | - | Fallback carrier for SMS gateway routing |
| CarrierGateways | `carrierGateways` | map[string]string | No | - | Carrier name to SMS-to-email gateway domain mapping |

```yaml
verification:
  codeLength: 6
  codeTTLSeconds: 300
  maxAttempts: 3
  transport: "smtp"
  smtp:
    host: "smtp.example.com"
    port: 587
    username: "signal-verify"
    password: "kms://secrets/smtp-password"
    fromAddress: "verify@example.com"
    useTLS: true
    defaultCarrier: "tmomail.net"
    carrierGateways:
      att: "txt.att.net"
      tmobile: "tmomail.net"
      verizon: "vtext.com"
```

---

## fido2

WebAuthn/FIDO2 authentication settings. Only available when the binary is built with the `fido2` build tag.

Source: `pkg/config/config_fido2.go`

| Field | YAML Key | Type | Required | Default | Description |
|---|---|---|---|---|---|
| Enabled | `enabled` | bool | No | `false` | Enable FIDO2 authentication |
| RPID | `rpId` | string | Yes* | - | Relying Party ID (typically the domain) |
| RPName | `rpName` | string | Yes* | - | Human-readable Relying Party name |
| RPOrigins | `rpOrigins` | []string | Yes* | - | Allowed origin URLs for WebAuthn ceremonies |
| Attestation | `attestation` | string | No | `"none"` | Attestation preference: `"none"`, `"indirect"`, `"direct"` |
| UserVerification | `userVerification` | string | No | `"preferred"` | User verification: `"required"`, `"preferred"`, `"discouraged"` |
| TimeoutSeconds | `timeoutSeconds` | int | No | `60` | Ceremony timeout in seconds |
| RequireMFA | `requireMfa` | bool | No | `false` | Require MFA for all accounts |
| AllowFIDO2Only | `allowFido2Only` | bool | No | `false` | Allow registration with FIDO2 only (no phone number) |

\* Required when `enabled: true`.

### Validation rules

When `enabled` is `true`:
- `rpId` must be non-empty
- `rpName` must be non-empty
- `rpOrigins` must contain at least one entry
- `attestation` must be one of: `"none"`, `"indirect"`, `"direct"` (or empty, which defaults to `"none"`)
- `userVerification` must be one of: `"required"`, `"preferred"`, `"discouraged"` (or empty, which defaults to `"preferred"`)

When `enabled` is `false`, all other fields are ignored and no validation is performed.

```yaml
fido2:
  enabled: true
  rpId: "signal.example.com"
  rpName: "Signal Server"
  rpOrigins:
    - "https://signal.example.com"
  attestation: "none"
  userVerification: "preferred"
  timeoutSeconds: 60
  requireMfa: false
  allowFido2Only: false
```

---

## Full example

A minimal production configuration:

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

verification:
  transport: "smtp"
  smtp:
    host: "smtp.internal"
    port: 587
    username: "verify"
    password: "kms://secrets/smtp-password"
    fromAddress: "verify@example.com"
    useTLS: true

turn:
  secret: "kms://secrets/turn-secret"
  uris:
    - "turn:turn.example.com:3478"

limits:
  messages:
    bucketSize: 256
    leakRatePerMin: 60
```

A minimal development configuration:

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
```
