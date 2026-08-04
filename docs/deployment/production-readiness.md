# Production Readiness

This document tracks what is required to run go-signal in production, what the
production-hardening pass delivered, and which items remain blocked (and on
what).

## Deployment model

The supported production topology is the **monolithic `signald` binary on the
PostgreSQL backend with a Redis cache**. The five auxiliary service binaries
(`cdsi`, `svr2`, `key-transparency`, `registration-service`, `storage-service`)
exist and build, but the horizontally-split topology is a future phase — see
[Remaining work](#remaining-work).

### How to deploy

1. Start from the production config template: [`configs/signal-server-prod.yml`](../../configs/signal-server-prod.yml).
   It sets `mode: production`, which activates the **fail-closed security gate**
   (`config.validateProduction`). The server refuses to boot if any
   development/test affordance is present.
2. Build the production image from the top-level `Dockerfile` (`make
   docker-build`). It ships **no secrets, config, or TLS certificates** — only
   the config template as `/etc/signal-server/config.yml.example`. Mount your
   real config at `/etc/signal-server/config.yml` and TLS certs at the paths it
   references.
3. Inject secrets via the `${VAR}` environment references in the config
   (resolved by `pkg/config/secrets`), or register a `kms://` resolver.

For a zero-dependency local demo use `Dockerfile.dev` (`make docker-build-dev` /
`make docker-run`), which bakes the in-memory test config. **Never deploy the
dev image.**

## What the production gate enforces

In `mode: production`, `config.Validate()` aggregates and rejects all of:

| Check | Rejected because |
|---|---|
| `storage.backend` not `postgres`/`file` | memory/qrdb(fake)/dynamodb(unimplemented) are not durable |
| `cache.backend` != `redis` | the memory cache breaks multi-instance delivery |
| `verification.transport` empty/`stub` | the stub only logs codes |
| `verification.fixedCode` non-empty | a fixed code bypasses verification |
| `captcha.provider` not `hcaptcha`/`recaptcha` | `test` accepts any token |
| `zkConfig` disabled or empty `serverSecret` | profile-key credentials downgrade to an insecure HMAC stub |
| `callingZkConfig.serverSecret` empty or the dev value | hardcoded test secret |
| missing `server.tlsCertFile`/`tlsKeyFile` | TLS is mandatory |
| `server.allowedOrigins` contains `*` | wildcard CORS/WebSocket origins |
| `limits.messages.bucketSize == 0` | a zero bucket disables the message spam check |
| any `*.remoteInsecure == true` | plaintext gRPC/HTTP to external services |

Runtime complements:
- Abuse checkers **fail closed** in production: a missing spam/fraud checker
  installs `spam.DenyAllChecker`/`DenyAllFraudChecker` (block) instead of the
  allow-all NoOp (`rest.ServerConfig.IsProduction`).
- A malformed `zkConfig.serverSecret` is **fatal** in production rather than
  silently downgrading to the HMAC placeholder.

## Remaining work

These are **not** code defects in what ships, but features/integrations that are
incomplete. None can be silently shipped — the production gate or a `501`
response surfaces each.

### Requires external credentials / accounts
- **Verification delivery** — Twilio Verify is wired (`pkg/verification/factory`
  → `twilio`); production requires real Twilio account/Verify-Service
  credentials. No other SMS/voice provider is implemented.
- **DeviceCheck** (`/v1/devicecheck/attest|assert`, 501) — needs Apple
  DeviceCheck credentials and the attestation verification crypto (the latter
  likely belongs in go-libsignal).
- **Subscriptions / donations** (`/v1/subscription/*`, `/v1/donation/*`, 501) —
  need Stripe integration and badge-receipt credential crypto.

### Requires further implementation
- **Key transparency** — `pkg/keytransparency/manager.go` sends a zero
  placeholder ACI; real JSON→proto mapping and proof generation are pending. KT
  search/monitor are not yet bound to the real account.
- **Real qrdb cluster transport** — `cmd/signald` uses an in-process
  `FakeKVStore` for the `qrdb` backend; a real cluster transport is a separate
  wire-up. Until then, **postgres is the production backend**.
- **DynamoDB backend** — advertised in config but unimplemented (selecting it
  is rejected by the production gate).
- **Aux-binary persistence** — `svr2`, `storage-service`, and
  `registration-service` can select qrdb/postgres stores; `cdsi` and
  `key-transparency` are memory-only and need persistent `Directory` /
  `ResumeTokenStore` / `Log` implementations before the service-split topology
  is production-ready.

### Dependency / environment
- **go-qrdb DAO secondary-index rebuild** — the DAO store does not rebuild the
  `Settings` secondary index on reopen, so credentials saved in one process
  aren't found cross-process. This blocks the CLI end-to-end integration tests
  and must be fixed in the go-qrdb dependency.
- **Java-parity test suite** — the 148 `TestSignalCLI_*` wire-compat tests need
  a built `signal-cli` (Gradle source at `/mnt/vm-host-1/signal-cli`) plus a
  JDK, provisioned in the devcontainer/CI.

## Verified

Unit coverage gate passes at **≥92%** (`make coverage`); backend, in-process API
integration, and the full frontend (Vitest + Playwright) suites are green.
