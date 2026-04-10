# Docker

go-signal ships with a multi-stage Dockerfile for production-style container builds and a docker-compose configuration for integration testing.

## Container Image

The Dockerfile uses a two-stage build:

1. **Builder stage** (`golang:1.26-bookworm`): Downloads dependencies, compiles `signald` with CGO disabled and stripped debug symbols (`-s -w`).
2. **Runtime stage** (`debian:bookworm-slim`): Installs only `ca-certificates` and `wget`, then copies in the binary, config file, and TLS certificates.

The runtime image exposes two ports:

| Port | Protocol | Purpose |
|---|---|---|
| 8080 | HTTP | REST API and WebSocket |
| 8443 | gRPC | Protobuf RPC |

The entrypoint runs:

```
signald start --config /etc/signal-server/config.yml
```

The Dockerfile copies `configs/signal-server.yml` as the base config and patches it at build time to set TLS certificate paths to `/etc/signal-server/tls/`.

## Build and Run

```bash
# Build the container image (tagged go-signal-dev:latest)
make docker-build

# Run the container with port mapping
make docker-run
```

`make docker-run` maps both 8080 and 8443 from the container to the host and removes the container on exit.

## Integration Testing Infrastructure

The project uses docker-compose to stand up the full test environment, including the go-signal server, a signal-cli instance, and an integration test runner. The compose file lives at `.devcontainer/docker-compose.yml`.

```bash
# Start the test infrastructure (detached, with rebuild)
make docker-compose-up

# Stop and remove volumes
make docker-compose-down

# Build the signal-cli test image separately
make docker-build-signal-cli
```

The signal-cli image is built from `test/signal-cli/` and provides a real Signal client for end-to-end testing against the server. See [testing.md](testing.md) for how integration tests use this infrastructure.
