# Two stages over one toolchain, for two different consumers.
#
#   toolchain    the interactive devcontainer. Developers mount their checkout
#                over /workspace and edit live, so it deliberately carries no
#                source.
#
#   integration  the same toolchain with the source baked in, for the CI
#                integration suite.
#
# The split exists because a bind mount cannot work from a Gitea Actions job.
# compose reaches the HOST daemon through the mounted docker socket, so it
# resolves `..:/workspace` against the HOST filesystem — and the job's checkout
# lives at /workspace/<owner>/<repo> INSIDE the job container, a path the host
# does not have. The daemon silently mounts an empty directory instead of
# failing, and the suite reports `make: No rule to make target
# 'integration-test'` with nothing to suggest the mount is the cause. That cost
# run 340. Baking the source in is also the honest CI shape: a test image should
# contain the code under test rather than borrow it from its surroundings.
#
# Both stages build with the REPOSITORY ROOT as context, which is why the CA
# cert below is addressed as .devcontainer/ca-cert.pem. .dockerignore excludes
# .devcontainer/ wholesale and re-admits exactly that one file.

FROM golang:1.26.6-bookworm AS toolchain

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

# Import test CA cert into Java trust store for signal-cli
COPY .devcontainer/ca-cert.pem /tmp/ca-cert.pem
RUN CACERTS=$(find /usr/lib/jvm -name cacerts -type f 2>/dev/null | head -1) && \
    if [ -n "$CACERTS" ]; then \
        keytool -importcert -trustcacerts -noprompt \
            -alias signal-test-ca \
            -file /tmp/ca-cert.pem \
            -keystore "$CACERTS" \
            -storepass changeit; \
    fi && \
    rm /tmp/ca-cert.pem

# Install Go tools
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest && \
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.7.2 && \
    go install github.com/securego/gosec/v2/cmd/gosec@latest && \
    go install golang.org/x/vuln/cmd/govulncheck@latest

WORKDIR /workspace

# The integration image. Source is copied, not mounted — see the note above.
# .dockerignore keeps this to the tree that matters: no .git, no build output,
# no node_modules, and none of the stale host-built service binaries at the
# repository root.
FROM toolchain AS integration

COPY . /workspace
