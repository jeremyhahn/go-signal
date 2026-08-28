# Two stages over one toolchain, for two different consumers.
#
#   toolchain    the interactive devcontainer. Developers mount their checkout
#                over /workspace and edit live, so it carries no source in the
#                final filesystem. It does COPY the Makefile transiently to read
#                the tool pins from it — deleted in the same layer, though still
#                recoverable from image history, which is fine: the Makefile is
#                public repository content, not a secret.
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

# Install Go tools, at the versions the MAKEFILE declares.
#
# Every version here used to be stated a second time, and the second statement
# drifted: three of these were @latest — so an image rebuild silently changed
# which scanner ran, and gosec@latest self-reports "Version: dev", which makes a
# scan result unattributable to any version — while golangci-lint was pinned to
# an abandoned v2.7.2 against the repo's documented v2.12.2. Two linters
# disagreeing, and the undocumented one is the one that gets believed when it
# happens to be quieter (#71).
#
# The Makefile is copied in FOR THIS, so the pins have exactly one definition
# and cannot drift again. It parses standalone — every version here is a plain
# := assignment — so no module or source tree is needed to read them.
#
# `make` comes from the apt layer above. To change a version, change the
# Makefile; nothing here needs editing.
#
# An empty version fails the build rather than installing something unpinned.
# `@v` with nothing after it is not obviously wrong at a glance, and the
# grpc plugin's leading "v" sits OUTSIDE the substitution, so that is exactly
# where an empty value would have looked plausible.
#
# ACCEPTED COST: copying the Makefile here means any Makefile edit invalidates
# this layer and reinstalls all five tools over the network. That is the price
# of one definition, and it is the right way round — a stale cached tool layer
# is a wrong scanner that nobody notices, while a slow rebuild is visible. This
# image is built on the integration path, not on every PR.
COPY Makefile /tmp/pins/Makefile
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

# The integration image. Source is copied, not mounted — see the note above.
# .dockerignore keeps this to the tree that matters: no .git, no build output,
# no node_modules, and none of the stale host-built service binaries at the
# repository root.
FROM toolchain AS integration

COPY . /workspace
