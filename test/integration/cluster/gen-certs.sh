#!/usr/bin/env bash
# Generates an ephemeral test CA + one certificate per Raft node for the 3-node
# mTLS cluster. go-quicraft mandates MTLSConfig when the QUIC raft transport is
# enabled, so the harness supplies operator-style PEM (CA / cert / key) exactly
# as a production deployment would via
# XKMS_CLUSTER_RAFT_TLS_{CA_CERT,CERT,KEY}_FILE.
#
# Each node gets its OWN keypair whose only hostname SAN is that node. A single
# shared certificate carrying every node's SAN is refused by the transport, and
# correctly so: a cert that names all three peers lets any replica present
# itself as any other, so mTLS would prove cluster membership but not identity —
# a compromised replica could impersonate the leader. Per-node SANs make the
# certificate an identity rather than a group badge.
#
# localhost / 127.0.0.1 stay on every cert because they are not peer addresses;
# they let a test dial a node directly without weakening peer identity.
#
# These are throwaway test certs — never use them outside this harness.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)/certs"
NODES=(node1 node2 node3)

mkdir -p "$DIR"

# Idempotent: regenerate on every run so the harness is self-contained.
rm -f "$DIR"/*.crt "$DIR"/*.key "$DIR"/*.srl "$DIR"/*.csr "$DIR"/*.cnf

# Test CA.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/ca.key" -out "$DIR/ca.crt" \
  -subj "/CN=xkms-cluster-test-ca" -days 3650 >/dev/null 2>&1

for node in "${NODES[@]}"; do
	openssl req -newkey rsa:2048 -nodes \
	  -keyout "$DIR/$node.key" -out "$DIR/$node.csr" \
	  -subj "/CN=$node" >/dev/null 2>&1

	cat > "$DIR/$node.cnf" <<EOF
subjectAltName=DNS:$node,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth,clientAuth
basicConstraints=critical,CA:FALSE
EOF

	openssl x509 -req -in "$DIR/$node.csr" \
	  -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
	  -out "$DIR/$node.crt" -days 3650 -extfile "$DIR/$node.cnf" >/dev/null 2>&1

	rm -f "$DIR/$node.csr" "$DIR/$node.cnf"
done

rm -f "$DIR/ca.srl" "$DIR/ca.key"
echo "✓ generated test cluster Raft mTLS certs in $DIR (ca.crt + per-node ${NODES[*]} cert/key)"
