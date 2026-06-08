#!/usr/bin/env bash
# Generates an ephemeral test CA + a shared node certificate for the 3-node Raft
# mTLS cluster. go-quicraft mandates MTLSConfig when the QUIC raft transport is
# enabled, so the harness supplies operator-style PEM (CA / cert / key) exactly
# as a production deployment would via XKMS_CLUSTER_RAFT_{CA_CERT,CERT,KEY}.
#
# A single cert with SANs for all three node hostnames is shared by every node:
# mTLS still proves cluster membership (CA-signed), and the SAN list satisfies
# both the serving and dialing sides for any node pair. These are throwaway test
# certs — never use them outside this harness.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$DIR"

# Idempotent: regenerate on every run so the harness is self-contained.
rm -f "$DIR"/*.crt "$DIR"/*.key "$DIR"/*.srl "$DIR"/*.csr "$DIR"/*.cnf

# Test CA.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/ca.key" -out "$DIR/ca.crt" \
  -subj "/CN=xkms-cluster-test-ca" -days 3650 >/dev/null 2>&1

# Shared node keypair + CSR.
openssl req -newkey rsa:2048 -nodes \
  -keyout "$DIR/node.key" -out "$DIR/node.csr" \
  -subj "/CN=xkms-cluster-node" >/dev/null 2>&1

cat > "$DIR/ext.cnf" <<'EOF'
subjectAltName=DNS:node1,DNS:node2,DNS:node3,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth,clientAuth
basicConstraints=critical,CA:FALSE
EOF

openssl x509 -req -in "$DIR/node.csr" \
  -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
  -out "$DIR/node.crt" -days 3650 -extfile "$DIR/ext.cnf" >/dev/null 2>&1

rm -f "$DIR/node.csr" "$DIR/ext.cnf" "$DIR/ca.srl" "$DIR/ca.key"
echo "✓ generated test cluster Raft mTLS certs in $DIR (ca.crt, node.crt, node.key)"
