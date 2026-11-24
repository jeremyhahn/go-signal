# syntax=docker/dockerfile:1.7
FROM golang:1.27.3-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./

# Private first-party modules resolve with credentials from an optional BuildKit secret, mounted for this RUN only and never in a layer.
RUN --mount=type=secret,id=gomodauth \
    set -eu; \
    if [ -f /run/secrets/gomodauth ]; then . /run/secrets/gomodauth; fi; \
    go mod download

COPY . .

ARG BUILD_TAGS="fido2"
RUN CGO_ENABLED=0 GOOS=linux go build -tags "${BUILD_TAGS}" -ldflags="-s -w" -o /signald ./cmd/signald/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /signald /usr/local/bin/signald

# Ships no config, secrets or certificates: mount a config at /etc/signal-server/config.yml and TLS files, inject secrets via ${VAR}; without a config the server refuses to start.
COPY configs/signal-server-prod.yml /etc/signal-server/config.yml.example

# Run as a non-root user.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin signal \
    && mkdir -p /etc/signal-server/tls \
    && chown -R signal:signal /etc/signal-server
USER signal

# Non-privileged HTTPS + gRPC ports (a load balancer forwards 443 -> 8443).
EXPOSE 8443 8444

ENTRYPOINT ["signald"]
CMD ["start", "--config", "/etc/signal-server/config.yml"]
