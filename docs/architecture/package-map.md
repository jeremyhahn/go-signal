# Package Map

Quick reference for every package in the go-signal codebase.

## Commands

| Package | Description |
|---------|-------------|
| `cmd/signald/` | Server daemon (cobra commands: start, version) |
| `cmd/signalctl/` | CLI control tool |

## Core Packages

| Package | Description |
|---------|-------------|
| `pkg/accounts/` | Account lifecycle management |
| `pkg/api/grpc/` | gRPC services and interceptors |
| `pkg/api/rest/` | REST HTTP/2 handlers |
| `pkg/api/websocket/` | WebSocket connection management |
| `pkg/auth/` | Authentication and authorization |
| `pkg/backup/` | Backup management |
| `pkg/badges/` | Badge management |
| `pkg/calling/` | Voice/video calling support |
| `pkg/captcha/` | Captcha verification |
| `pkg/certificates/` | Delivery certificates |
| `pkg/config/` | YAML configuration loading |
| `pkg/config/secrets/` | Secret URI resolution (`kms://`, `${ENV}`) |
| `pkg/devices/` | Multi-device management |
| `pkg/directory/` | Contact discovery |
| `pkg/errors/` | Shared typed errors |
| `pkg/fido2/` | WebAuthn/FIDO2 (build-tagged: `fido2`) |
| `pkg/groups/` | Group management |
| `pkg/keys/` | Pre-key bundle management |
| `pkg/keytransparency/` | Key transparency |
| `pkg/limits/` | Rate limiting |
| `pkg/messages/` | Message routing and storage |
| `pkg/metrics/` | Prometheus metrics |
| `pkg/profiles/` | Profile management |
| `pkg/push/` | Push notification dispatch (APN, FCM) |
| `pkg/registration/` | Account registration |
| `pkg/securestorage/` | Secure storage |
| `pkg/securevaluerecovery/` | SVR protocol |
| `pkg/spam/` | Spam detection |
| `pkg/stickers/` | Sticker pack management |
| `pkg/store/` | KVClient interface and implementations |
| `pkg/storage/` | Storage adapter layer |
| `pkg/subscriptions/` | Payment subscriptions |
| `pkg/usernames/` | Username management |
| `pkg/verification/` | Phone number verification |
| `pkg/verification/smtp/` | SMTP transport (build-tagged: `smtp`) |
| `pkg/websocket/` | WebSocket protocol handling |

## Test Packages

| Package | Description |
|---------|-------------|
| `test/integration/` | Integration tests |
| `test/performance/` | Benchmark documentation |
| `test/tls/` | TLS certificate test files |
| `test/signal-cli/` | Signal-cli test harness |
