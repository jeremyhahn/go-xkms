#!/usr/bin/env bash
# Generates a test CA and one certificate per Raft node for the 3-node mTLS cluster.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)/certs"
NODES=(node1 node2 node3)

mkdir -p "$DIR"

# Idempotent: regenerate on every run so the harness is self-contained.
rm -f "$DIR"/*.crt "$DIR"/*.key "$DIR"/*.srl "$DIR"/*.csr "$DIR"/*.cnf "$DIR"/cluster.env

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

# Raft member identities: go-quicraft admits a member by the SHA-256 of its
# certificate's SubjectPublicKeyInfo ("spki:<hex>", what qrdbd node-identity
# prints) and by nothing else, so every founding node names every member.
# The nodes read the list from cluster.env (docker-compose env_file).
identities=()
for i in "${!NODES[@]}"; do
	node="${NODES[$i]}"
	spki="$(openssl x509 -in "$DIR/$node.crt" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)"
	identities+=("$((i + 1))=spki:$spki")
done
(IFS=,; echo "XKMS_CLUSTER_MEMBER_IDENTITIES=${identities[*]}") > "$DIR/cluster.env"

rm -f "$DIR/ca.srl" "$DIR/ca.key"
echo "✓ generated test cluster Raft mTLS certs in $DIR (ca.crt + per-node ${NODES[*]} cert/key, cluster.env member identities)"
