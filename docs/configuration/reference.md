# Configuration Reference

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of the go-signal YAML configuration (`pkg/config`) and how `cmd/signald` consumes it.

The daemon reads a single YAML file. Source: `pkg/config/config.go` and the `config_*.go` files beside it.

## Loading

```bash
signald start --config /path/to/config.yaml
```

`--config` is a persistent flag on the root command (`cmd/signald/root.go`); it defaults to `configs/signal-server.yml`.

`config.Load` (`pkg/config/config.go`) does two steps:

1. **Parse YAML** into `Config` with `yaml.v3`. Fields typed `*secrets.SecureString` are sealed into protected memory as they decode. The raw file bytes are zeroed after parsing.
2. **Validate** (`Config.Validate`): requires `server.httpPort` or `server.grpcPort`, requires `storage.backend`, defaults `server.maxDevices` to `6`, and runs the production gate when `mode: production`.

A failed load wipes every secret it had already sealed. There is no secret-resolution step: `kms://`, `${VAR}` and sentinel values are kept as literal text. See [secrets.md](secrets.md).

| Error Type | Trigger |
|---|---|
| `ConfigLoadError` | File cannot be read |
| `ConfigParseError` | YAML is malformed or a value has the wrong type |
| `ConfigValidationError` | `server` has no port, or `storage.backend` is empty (`Field`, `Message`) |
| `ProductionValidationError` | `mode: production` and one or more violations; lists all of them |

Unknown YAML keys are ignored. Secret fields below are marked **secret**.

---

## mode

`mode: production` turns on the production gate (`validateProduction`); any other value, including empty, is development. The comparison is case-insensitive. The gate collects every violation into one `ProductionValidationError`:

- `storage.backend` is `postgres` or `file`.
- `cache.backend` is `redis`.
- `verification.transport` is not empty or `stub`; `verification.fixedCode` is empty; `verification.remoteInsecure` is false.
- `captcha.provider` is `hcaptcha` or `recaptcha`.
- `zkConfig.enabled` is true with a non-empty `zkConfig.serverSecret`.
- `callingZkConfig.serverSecret` is set and is not the well-known development secret.
- `cdn.bucket`, `cdn.region`, `cdn.accessKey` and `cdn.secretKey` are set, and the keys are not the development placeholders.
- `server.tlsCertFile` and `server.tlsKeyFile` are set; `server.allowedOrigins` has no `*`.
- `limits.messages.bucketSize` is greater than zero.
- `keyTransparency.remoteInsecure` and `storageService.remoteInsecure` are false.

---

## server

| YAML Key | Type | Default | Description |
|---|---|---|---|
| `host` | string | `""` (all interfaces) | Bind address |
| `httpPort` | int | - | HTTP/2 REST port |
| `grpcPort` | int | - | gRPC port |
| `tlsCertFile` | string | - | TLS certificate PEM path |
| `tlsKeyFile` | string | - | TLS private key PEM path |
| `maxDevices` | int | `6` | Maximum linked devices per account |
| `trustedProxies` | []string | - | Proxies whose forwarded client address is trusted |
| `allowedOrigins` | []string | - | Allowed CORS/WebSocket origins |

At least one of `httpPort` or `grpcPort` must be non-zero.

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

`backend` is required. `cmd/signald/start.go` switches on it:

| Value | Behaviour |
|---|---|
| `memory` | Ephemeral. Also the fallback for any unrecognised value, including `dynamodb` |
| `file` | KV store persisted under `storage.file.dataDir` |
| `postgres` | `storage.postgres`; migrations run at startup |
| `qrdb` | In-process fake KV transport; not durable |

### storage.file

| YAML Key | Type | Default | Description |
|---|---|---|---|
| `dataDir` | string | `data` (applied by the daemon) | Root directory for the file KV store |

### storage.dynamodb

Declared in the schema, not wired: `dynamodb` falls back to `memory`, and the production gate rejects it.

| YAML Key | Type | Description |
|---|---|---|
| `region`, `endpoint` | string | AWS region and custom endpoint |
| `accountsTable`, `messagesTable`, `keysTable`, `profilesTable` | string | Table names |
| `pendingAccountsTable` | string | Pending-accounts table |

### storage.postgres

`url`, when set, wins over the structured fields.

| YAML Key | Type | Default | Description |
|---|---|---|---|
| `url` | string, **secret** | - | libpq-style connection string |
| `host` | string | `localhost` | Host |
| `port` | int | `5432` | Port |
| `database` | string | - | Database name |
| `user` | string | - | User |
| `password` | string, **secret** | - | Password |
| `sslMode` | string | `disable` | `disable`, `require`, `verify-full`, ... Set it explicitly in production |
| `maxConns`, `minConns` | int | pgx default | Pool size bounds |
| `maxConnLifetime`, `maxConnIdleTime`, `connectTimeout` | duration | pgx default | Go durations, for example `30m` |

```yaml
storage:
  backend: "postgres"
  postgres:
    host: "db.internal"
    port: 5432
    database: "signal"
    user: "signal"
    password: "change-me"
    sslMode: "verify-full"
```

---

## cache

| YAML Key | Type | Description |
|---|---|---|
| `backend` | string | `redis` or `memory`; anything else uses the memory client. Production requires `redis` |
| `redis.url` | string | Redis URL |
| `redis.password` | string, **secret** | Redis password |
| `redis.db` | int | Database number (`0`) |

```yaml
cache:
  backend: "redis"
  redis:
    url: "redis://cache.internal:6379"
    password: "change-me"
```

---

## push

| YAML Key | Type | Description |
|---|---|---|
| `apn.teamId`, `apn.keyId`, `apn.bundleId` | string | Apple team, key and app identifiers |
| `apn.privateKey` | string, **secret** | APNs auth key |
| `apn.sandbox` | bool | Use the APNs sandbox (`false`) |
| `fcm.projectId` | string | Firebase project; empty falls back to the `project_id` in the credentials |
| `fcm.credentials` | string, **secret** | FCM service account JSON |

---

## cdn

| YAML Key | Type | Description |
|---|---|---|
| `bucket`, `region` | string | S3-compatible bucket and region |
| `accessKey`, `secretKey` | string, **secret** | Signing credentials |

---

## attachments, staticResources, frontend

| YAML Key | Type | Description |
|---|---|---|
| `attachments.storageDir` | string | Local directory for file-based attachment storage |
| `attachments.tusUri` | string | External TUS server URL; empty uses the embedded `/cdn3` endpoint |
| `attachments.tusSharedSecret` | string, **secret** | HMAC key the external TUS server validates |
| `staticResources.resourcesDir` | string | Served at `/resources/{path}` |
| `staticResources.updatesDir` | string | Served at `/updates/{path}` |
| `frontend.enabled` | bool | Serve the embedded web UI at `/` (`false`) |

---

## limits

Token-bucket limiters. Each key takes `bucketSize` (maximum burst) and `leakRatePerMin` (tokens refilled per minute). A zero field falls back to the default in `limits.DefaultConfig`.

| Key | Applies to (keyed by) |
|---|---|
| `registration` | Registration endpoints (IP) |
| `messages` | Message sends (account) |
| `preKeys` | Pre-key fetches (account) |
| `profiles` | Profile reads and writes (account) |
| `attachments` | Attachment uploads (account) |
| `verification` | Verification sessions (IP) |
| `pin` | PIN attempts (account) |
| `usernames` | Username operations (account) |
| `authentication` | Failed authentication (IP or account) |
| `accountCheck` | Account existence checks (IP) |
| `captchaAttempt`, `captchaSuccess` | Captcha attempts and successes (IP) |
| `deviceAllocate`, `deviceVerify` | Device provisioning (account) |
| `inboundMessageBytes` | Inbound message byte volume (account) |

The deprecated `profile` and `attachment` keys are not in the schema; use `profiles` and `attachments`.

```yaml
limits:
  messages:
    bucketSize: 256
    leakRatePerMin: 60
```

---

## fraud

Registration fraud detection. A zero value uses the default.

| YAML Key | Type | Default | Description |
|---|---|---|---|
| `maxRegistrationsPerIP` | int | `10` | Attempts per IP in the window |
| `maxRegistrationsPerPrefix` | int | `50` | Attempts per phone prefix in the window |
| `windowMinutes` | int | `60` | Rolling window |

---

## turn

Only Cloudflare TURN is configured; there is no shared-secret or `uris` key.

| YAML Key | Type | Description |
|---|---|---|
| `cloudflare.apiToken` | string, **secret** | Cloudflare TURN API token |
| `cloudflare.endpoint` | string | API endpoint |
| `cloudflare.urls`, `cloudflare.urlsWithIps` | []string | TURN URLs returned to clients |
| `cloudflare.hostname` | string | TURN hostname |
| `cloudflare.requestedCredentialTtl`, `cloudflare.clientCredentialTtl` | string | Credential lifetimes |
| `cloudflare.numHttpClients` | int | HTTP client pool size |

---

## zkConfig and callingZkConfig

| YAML Key | Type | Description |
|---|---|---|
| `zkConfig.enabled` | bool | Enable ZK credentials (`false`) |
| `zkConfig.serverSecret` | string, **secret** | ZK server secret |
| `zkConfig.signingKey` | string, **secret** | Signing key |
| `callingZkConfig.serverSecret` | string, **secret** | Call-link credential secret |

---

## callQualitySurvey

| YAML Key | Type | Description |
|---|---|---|
| `backend` | string | `log` or `pubsub` |
| `pubSub.projectId`, `pubSub.topicId` | string | Google Cloud Pub/Sub target |

---

## payments

| YAML Key | Type | Description |
|---|---|---|
| `stripe.apiKey` | string, **secret** | Stripe API key |
| `stripe.webhookSecret` | string, **secret** | Webhook signing secret |

---

## directory

| YAML Key | Type | Description |
|---|---|---|
| `enabled` | bool | Enable the contact discovery directory (`false`) |

---

## storageService

`remoteUrl` selects the mode. Empty enables the in-process storage-service and signald serves `/storage` itself (`cmd/signald/start.go`). When set, signald acts only as an admin client and the in-process `/storage` routes stay on the `204` stub.

| YAML Key | Type | Default | Description |
|---|---|---|---|
| `httpListen` | string | `0.0.0.0:8096` (standalone binary) | Bind address of `cmd/storage-service` |
| `sharedSecret` | string, **secret** | - | HMAC secret shared with storage-service. Not enforced at load; unset selects the legacy stub that mints random-UUID credentials (`SecureStorageManager.SetSharedSecret`), which a real storage-service rejects |
| `remoteUrl` | string | `""` | storage-service admin endpoint |
| `remoteInsecure` | bool | `false` | Allow plaintext HTTP; rejected in production |

---

## svr2, cdsi, keyTransparency

Settings for the standalone `svr2`, `cdsi` and `key-transparency` binaries and signald's clients for them.

| YAML Key | Type | Description |
|---|---|---|
| `svr2.httpListen`, `svr2.wsListen` | string | Binary listeners (`0.0.0.0:8091`, `0.0.0.0:8092`) |
| `svr2.attestation` | string | `software` (default) or `tpm`; standalone binaries must use `software` |
| `svr2.sharedSecret` | string, **secret** | HMAC secret for SVR2 credentials |
| `svr2.remoteUrl` | string | Admin endpoint signald calls; empty disables it |
| `cdsi.wsListen` | string | WebSocket listener (`0.0.0.0:8094`) |
| `cdsi.attestation` | string | `software` (default) or `tpm` |
| `cdsi.sharedSecret` | string, **secret** | HMAC secret shared with signald |
| `cdsi.signaldDirectoryAddr` | string | signald DirectoryService gRPC address |
| `cdsi.signaldDirectoryInsecure` | bool | Plaintext gRPC to signald |
| `keyTransparency.grpcListen` | string | Binary gRPC listener (`0.0.0.0:8098`) |
| `keyTransparency.remoteAddr` | string | KT gRPC endpoint signald calls; empty uses the in-process manager |
| `keyTransparency.remoteInsecure` | bool | Plaintext gRPC; rejected in production |

---

## remoteConfig and backups

| YAML Key | Type | Description |
|---|---|---|
| `remoteConfig.defaults` | list | Feature flags upserted at boot: `name`, `percentage`, `value`, `defaultValue`, `hashKey`, `uuids` |
| `remoteConfig.refreshInterval` | duration | Store re-read interval; zero means 10 seconds |
| `backups.enabled` | bool | Build the backups subsystem (`false`) |
| `backups.blob.backend` | string | `filesystem` is the only implementation |
| `backups.blob.root` | string | Directory for the filesystem backend |
| `backups.blob.cdnNumber` | int | CDN number; default `3` |
| `backups.expiryGraceHours` | int | Refresh grace; zero uses 30 days |
| `backups.maxTotalMediaSize` | int | Per-user media quota in bytes; zero uses 100 GiB |

---

## captcha

Source: `pkg/config/config_captcha.go`.

| YAML Key | Type | Default | Description |
|---|---|---|---|
| `provider` | string | `test` | `hcaptcha`, `recaptcha` or `test`. `test` accepts any token; production rejects it |
| `secretKey` | string, **secret** | - | Upstream verification secret; not needed for `test` |
| `siteKey` | string | - | Public site key |
| `scoreThreshold` | float | `0.5` when zero | Minimum reCAPTCHA v3 score, in [0.0, 1.0] |
| `siteKeysByAction` | map[string][]string | - | Allowed site keys per action (`challenge`, `registration`); empty accepts any |

---

## verification

Source: `pkg/config/config_verification.go`.

| YAML Key | Type | Default | Description |
|---|---|---|---|
| `transport` | string | `stub` | `stub` or `twilio`. `smtp` is not accepted by the daemon (see below) |
| `codeLength` | int | `6` | Digits in a code |
| `codeTTLSeconds` | int | `300` | Code lifetime |
| `maxAttempts` | int | `3` | Submissions per session |
| `fixedCode` | string | - | Static code for integration tests with the `stub` transport; the daemon refuses it with any other transport, and production rejects it |
| `remoteAddr` | string | - | gRPC address of an external registration-service; empty embeds verification in signald |
| `remoteInsecure` | bool | `false` | Plaintext gRPC to `remoteAddr`; rejected in production |
| `grpcListen` | string | `0.0.0.0:8090` | Listener of `cmd/registration-service`; signald ignores it |

`codeLength`, `codeTTLSeconds` and `maxAttempts` are passed to the registration core only by `cmd/registration-service`; the monolithic daemon uses the core defaults, which equal the table values. `stub` logs the code and never delivers it.

`pkg/verification/factory.Build` is the single transport selector. It knows `stub` (or empty) and `twilio`; any other value, `smtp` included, fails with an invalid-argument error. The `smtp` package (`pkg/verification/smtp`, build tag `smtp`) is not referenced by the factory or by `cmd/`, so `verification.smtp` is parsed and its password is wiped, but nothing in the daemon consumes it.

### verification.twilio

| YAML Key | Type | Default | Description |
|---|---|---|---|
| `accountSid` | string | - | Account SID (Basic username) |
| `authToken` | string, **secret** | - | Auth token (Basic password) |
| `verifyServiceSid` | string | - | Verify Service SID |
| `channel` | string | `sms` | `sms`, `call` or `whatsapp` |

### verification.smtp

Parsed but not consumed by the daemon.

| YAML Key | Type | Description |
|---|---|---|
| `host`, `port`, `username` | string, int, string | SMTP server and login |
| `password` | string, **secret** | SMTP password |
| `fromAddress` | string | Sender address |
| `useTLS` | bool | Enable TLS |
| `defaultCarrier` | string | Fallback carrier |
| `carrierGateways` | map[string]string | Carrier to SMS-gateway domain |

---

## fido2

Defined in `pkg/config/config_fido2.go` (build tag `fido2`). Details and defaults are in [../auth/fido2.md](../auth/fido2.md). `requireMfa` and `allowFido2Only` are reported by `GET /v1/fido2/capabilities` and enforced nowhere.

---

## Examples

Development:

```yaml
server:
  httpPort: 8080

storage:
  backend: "memory"

cache:
  backend: "memory"

verification:
  transport: "stub"
```

Production skeleton (every key below is checked by the production gate):

```yaml
mode: production

server:
  httpPort: 8080
  grpcPort: 9090
  tlsCertFile: /etc/signal/tls/cert.pem
  tlsKeyFile: /etc/signal/tls/key.pem

storage:
  backend: "postgres"
  postgres:
    host: "db.internal"
    database: "signal"
    user: "signal"
    password: "change-me"
    sslMode: "verify-full"

cache:
  backend: "redis"
  redis:
    url: "redis://cache.internal:6379"

verification:
  transport: "twilio"
  twilio:
    accountSid: "AC..."
    authToken: "change-me"
    verifyServiceSid: "VA..."

captcha:
  provider: "hcaptcha"
  secretKey: "change-me"

zkConfig:
  enabled: true
  serverSecret: "change-me"

callingZkConfig:
  serverSecret: "change-me"

cdn:
  bucket: "signal-attachments"
  region: "us-east-1"
  accessKey: "change-me"
  secretKey: "change-me"

limits:
  messages:
    bucketSize: 256
    leakRatePerMin: 60
```
