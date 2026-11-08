#!/bin/bash
set -euo pipefail

# Generate the test TLS material the integration stack uses: a throwaway CA and
# a server certificate it issued. Nothing here is committed. `make test-tls`
# runs this before the integration suite and the images that need it, and
# regenerates when the material is missing or about to expire.
#
#   CERT_DIR  output directory (default: this script's directory, test/tls)
#   HOSTNAME  server name the leaf is issued for (default: signal-server)
#   DAYS      validity in days (default: 30; short-lived on purpose)
#
# ECDSA P-256 keys, written 0600. The CA key is deleted once the leaf is signed:
# nothing needs to issue a second certificate from it, and a key that does not
# exist cannot leak. Re-run the script for a new pair.

CERT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
HOSTNAME="${2:-signal-server}"
DAYS="${DAYS:-30}"

mkdir -p "${CERT_DIR}"
umask 077
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# CA key and self-signed certificate
openssl ecparam -name prime256v1 -genkey -noout -out "${work}/ca-key.pem"
openssl req -x509 -new -sha256 \
    -key "${work}/ca-key.pem" \
    -out "${work}/ca-cert.pem" \
    -days "${DAYS}" \
    -subj "/CN=Signal Test CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# Server key and CSR
openssl ecparam -name prime256v1 -genkey -noout -out "${work}/server-key.pem"
openssl req -new -sha256 \
    -key "${work}/server-key.pem" \
    -out "${work}/server.csr" \
    -subj "/CN=${HOSTNAME}"

cat > "${work}/san.cnf" << CNF
[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${HOSTNAME}
DNS.2 = localhost
IP.1 = 127.0.0.1
CNF

# Server certificate, signed by the CA
openssl x509 -req -sha256 \
    -in "${work}/server.csr" \
    -CA "${work}/ca-cert.pem" \
    -CAkey "${work}/ca-key.pem" \
    -CAcreateserial \
    -out "${work}/server-cert.pem" \
    -days "${DAYS}" \
    -extensions v3_req \
    -extfile "${work}/san.cnf"

# Publish the certificates and the server key; the CA key stays in ${work} and
# goes with it. The certificates are public material, so they are made
# world-readable for the image builds; the server key stays 0600.
install -m 0644 "${work}/ca-cert.pem" "${CERT_DIR}/ca-cert.pem"
install -m 0644 "${work}/server-cert.pem" "${CERT_DIR}/server-cert.pem"
install -m 0600 "${work}/server-key.pem" "${CERT_DIR}/server-key.pem"

echo "Test TLS material generated in ${CERT_DIR} (valid ${DAYS} days)"
