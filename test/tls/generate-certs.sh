#!/bin/bash
set -euo pipefail

# Generate self-signed TLS certificates for integration testing.
# Creates a CA and server certificate trusted by both Go and Java clients.

CERT_DIR="${1:-/etc/signal-server/tls}"
HOSTNAME="${2:-signal-server}"

mkdir -p "${CERT_DIR}"

# Generate CA private key and certificate
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${CERT_DIR}/ca-key.pem" \
    -out "${CERT_DIR}/ca-cert.pem" \
    -days 3650 \
    -subj "/CN=Signal Test CA"

# Generate server private key and CSR
openssl req -newkey rsa:2048 -nodes \
    -keyout "${CERT_DIR}/server-key.pem" \
    -out "${CERT_DIR}/server.csr" \
    -subj "/CN=${HOSTNAME}"

# Create SAN extension config
cat > "${CERT_DIR}/san.cnf" << EOF
[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${HOSTNAME}
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# Sign server certificate with CA
openssl x509 -req \
    -in "${CERT_DIR}/server.csr" \
    -CA "${CERT_DIR}/ca-cert.pem" \
    -CAkey "${CERT_DIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${CERT_DIR}/server-cert.pem" \
    -days 3650 \
    -extensions v3_req \
    -extfile "${CERT_DIR}/san.cnf"

# Clean up intermediate files
rm -f "${CERT_DIR}/server.csr" "${CERT_DIR}/san.cnf" "${CERT_DIR}/ca-cert.srl"

echo "TLS certificates generated in ${CERT_DIR}"
echo "  CA cert:     ${CERT_DIR}/ca-cert.pem"
echo "  Server cert: ${CERT_DIR}/server-cert.pem"
echo "  Server key:  ${CERT_DIR}/server-key.pem"
