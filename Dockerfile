FROM golang:1.26-bookworm AS builder

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
COPY configs/signal-server.yml /etc/signal-server/config.yml
COPY test/tls/server-cert.pem /etc/signal-server/tls/server-cert.pem
COPY test/tls/server-key.pem /etc/signal-server/tls/server-key.pem
COPY test/tls/ca-cert.pem /etc/signal-server/tls/ca-cert.pem

# Configure TLS cert paths in config
RUN sed -i 's|tlsCertFile: ""|tlsCertFile: "/etc/signal-server/tls/server-cert.pem"|' /etc/signal-server/config.yml && \
    sed -i 's|tlsKeyFile: ""|tlsKeyFile: "/etc/signal-server/tls/server-key.pem"|' /etc/signal-server/config.yml

EXPOSE 8081 8443

ENTRYPOINT ["signald"]
CMD ["start", "--config", "/etc/signal-server/config.yml"]
