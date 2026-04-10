FROM golang:1.26-bookworm

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
COPY ca-cert.pem /tmp/ca-cert.pem
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
