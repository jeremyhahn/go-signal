# Stages: toolchain (the devcontainer, source mounted) and integration (source baked in, since a CI bind mount resolves on the host daemon).
# The test CA comes from the named build context `tls`: docker build --build-context tls=test/tls -f .devcontainer/Dockerfile .

FROM golang:1.27.3-bookworm AS toolchain

# Install JRE 21 from Eclipse Temurin for signal-cli compatibility
RUN apt-get update && apt-get install -y --no-install-recommends \
    make \
    git \
    protobuf-compiler \
    build-essential \
    wget \
    apt-transport-https \
    && rm -rf /var/lib/apt/lists/*

# Install Eclipse Temurin JRE 21
RUN wget -qO- https://packages.adoptium.net/artifactory/api/gpg/key/public | tee /etc/apt/keyrings/adoptium.asc > /dev/null && \
    echo "deb [signed-by=/etc/apt/keyrings/adoptium.asc] https://packages.adoptium.net/artifactory/deb bookworm main" | tee /etc/apt/sources.list.d/adoptium.list && \
    apt-get update && apt-get install -y --no-install-recommends temurin-21-jre && \
    rm -rf /var/lib/apt/lists/*

# Import the test CA into the Java trust store for signal-cli; cacerts is a symlink, hence find -L, and a missing store fails the build.
COPY --from=tls ca-cert.pem /tmp/ca-cert.pem
RUN CACERTS=$(find -L /usr/lib/jvm -name cacerts -type f 2>/dev/null | head -1) && \
    [ -n "$CACERTS" ] || { echo "no Java cacerts under /usr/lib/jvm" >&2; exit 1; }; \
    keytool -importcert -trustcacerts -noprompt \
        -alias signal-test-ca \
        -file /tmp/ca-cert.pem \
        -keystore "$CACERTS" \
        -storepass changeit && \
    rm /tmp/ca-cert.pem

# Install Go tools at the versions the Makefile pins; to change a version, change the Makefile. An empty version fails the build.
COPY Makefile /tmp/pins/Makefile
# The Makefile includes mk/release-alpha.mk, which includes mk/release-common.mk.
COPY mk/ /tmp/pins/mk/
RUN set -eux; \
    cd /tmp/pins; \
    pin() { \
        v="$(make -s "$1")"; \
        [ -n "$v" ] || { echo "empty version from $1 — refusing to install unpinned" >&2; exit 1; }; \
        printf '%s' "$v"; \
    }; \
    go install google.golang.org/protobuf/cmd/protoc-gen-go@"$(pin print-protoc-gen-go-version)"; \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v"$(pin print-protoc-gen-go-grpc-version)"; \
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@"$(pin print-golangci-lint-version)"; \
    go install github.com/securego/gosec/v2/cmd/gosec@"$(pin print-gosec-version)"; \
    go install golang.org/x/vuln/cmd/govulncheck@"$(pin print-govulncheck-version)"; \
    rm -rf /tmp/pins

WORKDIR /workspace

# The integration image: source is copied, not mounted; .dockerignore limits the tree.
FROM toolchain AS integration

COPY . /workspace
