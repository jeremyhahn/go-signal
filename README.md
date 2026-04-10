# go-signal

A Signal messaging server written in Go. Implements the Signal protocol server API with support for account registration, end-to-end encrypted messaging, pre-key distribution, profile management, multi-device linking, and real-time WebSocket delivery.

Built as a Go port of the official [Signal-Server](https://github.com/signalapp/Signal-Server) (Java), using [go-libsignal](https://github.com/jeremyhahn/go-libsignal) for cryptographic protocol operations.

## Quick Start

### Prerequisites

- Go 1.26+
- Make

### Build and Run

```bash
# Build the server and CLI
make build

# Start with the default in-memory config
./build/bin/signald start --config configs/signal-server.yml
```

The server starts on port 8080 (HTTP/2 REST) and 8443 (gRPC) by default. With the default config, all data is stored in memory and verification codes are logged to stdout.

### Docker

```bash
make docker-build
make docker-run
```

### Register an Account

```bash
# 1. Create a verification session
curl -X POST https://localhost:8080/v1/verification/session \
  -H "Content-Type: application/json" \
  -d '{"number": "+15551234567"}'

# 2. Request a verification code (check server stdout for the code)
curl -X POST https://localhost:8080/v1/verification/session/{session_id}/code \
  -H "Content-Type: application/json" \
  -d '{"transport": "sms"}'

# 3. Submit the verification code
curl -X PUT https://localhost:8080/v1/verification/session/{session_id}/code \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'

# 4. Register the account
curl -X POST https://localhost:8080/v1/registration \
  -H "Content-Type: application/json" \
  -d '{
    "sessionId": "...",
    "accountAttributes": {
      "fetchesMessages": true,
      "registrationId": 12345,
      "pniRegistrationId": 67890
    }
  }'
```

### Send a Message

```bash
curl -X PUT https://localhost:8080/v1/messages/{destination_uuid} \
  -u "your-uuid:your-auth-token" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [{
      "type": 1,
      "destinationDeviceId": 1,
      "content": "base64-encoded-ciphertext"
    }]
  }'
```

## Build Variants

```bash
make build          # Base server (core Signal functionality)
make build-fido2    # + WebAuthn/FIDO2 authentication (requires libfido2-dev)
make build-smtp     # + SMTP-based SMS verification
make build-all      # All extensions
```

## Testing

```bash
make test                 # Run all unit tests
make test-accounts        # Run tests for a specific package
make integration-test     # Run E2E integration tests
make coverage             # Generate coverage report (90% minimum)
```

## Configuration

The server reads a single YAML config file. See [`configs/signal-server.yml`](configs/signal-server.yml) for the default template.

Secrets can be provided as:
- `kms://` URIs for KMS-managed secrets
- `${ENV_VAR}` references for environment variable injection
- `"auto"` sentinel for development (generates random secrets at startup)

See [Configuration Reference](docs/configuration/reference.md) for all options.

## Documentation

### Architecture

| Document | Description |
|----------|-------------|
| [Architecture Overview](docs/architecture/overview.md) | Three-layer design, protocol compliance, build tags |
| [Package Map](docs/architecture/package-map.md) | Every package with a one-line description |

### API

| Document | Description |
|----------|-------------|
| [REST API Reference](docs/api/rest.md) | All HTTP endpoints with request/response examples |
| [WebSocket Protocol](docs/api/websocket.md) | Real-time messaging, provisioning, keepalive |

### Authentication

| Document | Description |
|----------|-------------|
| [Authentication](docs/auth/authentication.md) | Basic Auth, registration modes, security properties |
| [FIDO2/WebAuthn](docs/auth/fido2.md) | Hardware key support, ceremonies, credential management |

### Verification

| Document | Description |
|----------|-------------|
| [Verification](docs/verification/verification.md) | Phone number verification flow and transport layer |
| [SMTP SMS Gateway](docs/verification/smtp-gateway.md) | SMS delivery via carrier email gateways |

### Configuration

| Document | Description |
|----------|-------------|
| [Configuration Reference](docs/configuration/reference.md) | All config sections, fields, and validation rules |
| [Secrets Management](docs/configuration/secrets.md) | KMS URIs, env vars, auto-generation, custom resolvers |

### Storage

| Document | Description |
|----------|-------------|
| [Storage Overview](docs/storage/overview.md) | KVClient interface, backends, domain stores |

### Messaging

| Document | Description |
|----------|-------------|
| [Messaging Overview](docs/messaging/overview.md) | Message types, delivery pipeline, WebSocket push |

### Deployment

| Document | Description |
|----------|-------------|
| [Building](docs/deployment/building.md) | Build targets, build tags, version injection |
| [Docker](docs/deployment/docker.md) | Container deployment, docker-compose |
| [Testing](docs/deployment/testing.md) | Unit tests, integration tests, coverage, CI pipeline |

## Project Structure

```
cmd/
  signald/              Server daemon
  signalctl/            CLI client

pkg/
  accounts/             Account lifecycle
  api/rest/             HTTP/2 REST API
  api/grpc/             gRPC services
  api/websocket/        WebSocket handler
  auth/                 Authentication
  config/               Configuration loading
  config/secrets/       Secret URI resolution
  devices/              Multi-device management
  fido2/                FIDO2/WebAuthn (build-tagged)
  keys/                 Pre-key distribution
  messages/             Message routing and storage
  profiles/             Profile management
  store/                KVClient interface
  verification/         Phone verification
  verification/smtp/    SMTP transport (build-tagged)
  websocket/            WebSocket sessions
  ...                   See package map for all packages
```

## License

[AGPL-3.0](LICENSE)
