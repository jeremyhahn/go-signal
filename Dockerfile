FROM golang:1.26.3-bookworm AS builder

WORKDIR /app

# Copy local replace-directive dependencies (provided via additional_contexts)
COPY --from=go-libsignal . /go-libsignal
COPY --from=go-xkms . /go-xkms
COPY --from=go-qrdb . /go-qrdb
COPY --from=go-quicraft . /go-quicraft

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG BUILD_TAGS="fido2"
RUN CGO_ENABLED=0 GOOS=linux go build -tags "${BUILD_TAGS}" -ldflags="-s -w" -o /signald ./cmd/signald/

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /signald /usr/local/bin/signald

# This image is hardened for production and ships NO active configuration,
# secrets, or TLS certificates. It bundles ONLY the production config TEMPLATE
# as a reference. At deploy time the operator must:
#   1. Mount a real config at /etc/signal-server/config.yml (start from the
#      bundled template; it sets `mode: production`, which activates the
#      fail-closed security gate in pkg/config.validateProduction).
#   2. Mount real TLS certificates at the paths the config references.
#   3. Inject secrets via the ${VAR} environment references in the config.
# With no mounted config the server fails to start (fail-closed) rather than
# silently running a development/test instance.
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
