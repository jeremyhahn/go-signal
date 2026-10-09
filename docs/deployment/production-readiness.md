# Production Readiness

> **Status: REFERENCE** · Last verified: 2026-10-09
> What running go-signal in production requires: the deployment model, the production config gate and the known incomplete areas.

This document lists what is required to run go-signal in production, what the
fail-closed gate enforces, and which items remain incomplete (and why).

## Deployment model

The supported production topology is the **monolithic `signald` binary on the
PostgreSQL backend with a Redis cache**. The five auxiliary service binaries
(`cdsi`, `svr2`, `key-transparency`, `registration-service`, `storage-service`)
exist and build, but the horizontally-split topology is not production-ready —
see [Remaining work](#remaining-work).

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
| `storage.backend` not `postgres`/`file` | memory/qrdb(in-process fake)/dynamodb(unimplemented, falls through to memory) are not durable |
| `cache.backend` != `redis` | the memory cache breaks multi-instance delivery |
| `verification.transport` empty/`stub` | the stub only logs codes |
| `verification.fixedCode` non-empty | a fixed code bypasses verification |
| `captcha.provider` not `hcaptcha`/`recaptcha` | `test` accepts any token |
| `zkConfig` disabled or empty `serverSecret` | profile-key credentials downgrade to an insecure HMAC stub |
| `callingZkConfig.serverSecret` empty or the dev value | hardcoded test secret |
| `cdn.bucket`, `cdn.region`, `cdn.accessKey` or `cdn.secretKey` empty, or the development placeholder keys | avatar and attachment upload signing would fail |
| missing `server.tlsCertFile`/`tlsKeyFile` | TLS is mandatory |
| `server.allowedOrigins` contains `*` | wildcard CORS/WebSocket origins |
| `limits.messages.bucketSize == 0` | a zero bucket disables the message spam check |
| `verification.remoteInsecure`, `keyTransparency.remoteInsecure` or `storageService.remoteInsecure` true | plaintext gRPC/HTTP to external services |

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
  credentials. The gate's message names `smtp` as acceptable, but the factory
  does not wire it (see [../verification/smtp-gateway.md](../verification/smtp-gateway.md)),
  so `twilio` is the only transport that works in production.
- **DeviceCheck** (`/v1/devicecheck/attest|assert`, 501) — needs Apple
  DeviceCheck credentials and the attestation verification crypto (the latter
  likely belongs in go-libsignal).
- **Subscriptions / donations** (`/v1/subscription/*`, `/v1/donation/*`, 501) —
  need Stripe integration and badge-receipt credential crypto.

### Requires further implementation
- **Key transparency** — `pkg/keytransparency/manager.go` sends a placeholder
  ACI identity key in its request until the real mapping is wired, so
  search/monitor are not bound to the real account.
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
  and must be fixed in the go-qrdb dependency. (Stated from the project's
  records; not re-checked against go-qrdb.)
- **Java-parity test suite** — the `TestSignalCLI_*` wire-compat tests under
  `test/` need a built `signal-cli` plus a JDK, provisioned in the
  devcontainer/CI.
