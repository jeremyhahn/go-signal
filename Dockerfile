# syntax=docker/dockerfile:1.7
FROM golang:1.27.4-bookworm AS builder

WORKDIR /app

COPY go.mod go.sum ./

# The four `COPY --from=go-libsignal|go-xkms|go-qrdb|go-quicraft` lines that
# stood here were residue of the pre-2026-08 local-replace layout. go.mod has
# carried no local-path replaces since the cutover — every first-party
# dependency is a tagged module fetched from Gitea — so the copies fed nothing;
# they only made the image unbuildable outside .devcontainer/docker-compose.yml,
# which was the sole supplier of those build contexts, and unbuildable anywhere
# at all on a CI runner, which has no sibling working copies.
#
# What the build genuinely needs instead is credentials for the internal Gitea
# host: GOPRIVATE plus git's insteadOf rewrite carrying a read-only token
# (conventions/dependency-resolution.md §6). They arrive as a BuildKit secret,
# NOT a build arg — a build arg is recorded in image metadata and readable with
# `docker history` — and are sourced rather than exported so the value never
# reaches a command line either. The mount is tmpfs for this RUN alone and
# never becomes a layer.
#
# The mount is optional by design: where no secret is supplied, as on GitHub,
# these modules resolve from the public proxy once tags are mirrored, so the
# same Dockerfile builds on both hosts.
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
