FROM eclipse-temurin:21-jdk-jammy AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    python3 \
    && rm -rf /var/lib/apt/lists/*

ARG SIGNAL_SERVER_URL=https://signal-server:8080

COPY build-signal-cli.sh /tmp/build-signal-cli.sh
COPY ca-cert.pem /tmp/ca-cert.pem
RUN chmod +x /tmp/build-signal-cli.sh && \
    SIGNAL_SERVER_URL=${SIGNAL_SERVER_URL} /tmp/build-signal-cli.sh

FROM eclipse-temurin:21-jre-jammy

COPY --from=builder /opt/signal-cli /opt/signal-cli
RUN ln -s /opt/signal-cli/bin/signal-cli /usr/local/bin/signal-cli

# Import the test CA cert into Java's trust store
COPY ca-cert.pem /tmp/ca-cert.pem
RUN keytool -importcert -trustcacerts -noprompt \
    -alias signal-test-ca \
    -file /tmp/ca-cert.pem \
    -keystore ${JAVA_HOME}/lib/security/cacerts \
    -storepass changeit

# Also install the CA cert into the OS trust store so native libraries
# (OkHttp, libsignal-net) trust the self-signed server certificate.
RUN cp /tmp/ca-cert.pem /usr/local/share/ca-certificates/signal-test-ca.crt && \
    update-ca-certificates && \
    rm /tmp/ca-cert.pem

# Create data directory for signal-cli
RUN mkdir -p /var/lib/signal-cli
ENV SIGNAL_CLI_DATA=/var/lib/signal-cli

ENTRYPOINT ["signal-cli", "--config", "/var/lib/signal-cli"]
