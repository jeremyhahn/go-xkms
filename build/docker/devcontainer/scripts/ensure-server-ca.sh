#!/bin/bash
# ensure-server-ca.sh — publish the xkms server's root CA and admin credential
# where the PKCS#11 integration suites expect to find them: the compose
# xkms-server's, or without it the one scripts/start-test-xkmsd.sh started.
#
# The gRPC-over-TCP lane of test/integration/pkcs11/module dials
# xkms-server:9443, which serves TLS with a certificate the daemon issues from
# the CA it initializes on first start. The suite loads the root to trust from
# XKMS_GRPC_TLS_CA; without it C_Initialize fails with CKR_GENERAL_ERROR (the
# module cannot build its credentials) and every /grpc subtest goes red while
# the /unix subtests pass — a failure mode that looks like a protocol bug and is
# not one.
#
# Two details make this a script rather than a bind mount:
#
#   * The CA is created at RUNTIME, into the xkms-data volume, so there is no
#     host path to mount. The volume is mounted read-only at /xkms-data instead.
#   * The daemon's certificate store writes DER bytes into files named `.pem`.
#     Go's x509.CertPool.AppendCertsFromPEM and OpenSSL's -CAfile both reject
#     that outright ("no certificate or crl found"), so the bytes are sniffed
#     and converted to PEM here.
#
# The root is identified as the certificate whose subject equals its issuer,
# rather than by filename: the filename is the CA's CN from
# configs/xkmsd-integration.yaml and would silently break if that CN changed.
#
# Usage:
#   ensure-server-ca.sh          # write $XKMS_GRPC_TLS_CA, or exit non-zero
# Environment:
#   XKMS_SERVER_STATE_DIR   read-only xkms-server state mount (default /xkms-data)
#   XKMS_GRPC_TLS_CA        destination PEM file      (default /tmp/xkms/ca.crt)
#   XKMS_COMPOSE_SERVER_HOST  compose server service name (default xkms-server)
#   XKMS_SERVER_BOOTSTRAP_URL trust-bootstrap endpoint
#                             (default https://<compose server>:8443/v1/ca/bootstrap)
#   XKMS_TEST_DATA_DIR      start-test-xkmsd.sh data directory, read when the
#                           compose server is not running (default /tmp/xkmsd-test)
#   XKMS_TEST_REST_PORT     its loopback REST port (default 18443)

set -euo pipefail

STATE_DIR="${XKMS_SERVER_STATE_DIR:-/xkms-data}"
DEST="${XKMS_GRPC_TLS_CA:-/tmp/xkms/ca.crt}"
CERT_DIR="${STATE_DIR}/storage/ca/certs"
COMPOSE_SERVER_HOST="${XKMS_COMPOSE_SERVER_HOST:-xkms-server}"

# publish_admin_credential copies the first-boot administrator credential
# alongside the CA. First boot (qrdb pkg/firstboot) binds the admin's SPKI
# thumbprint and writes the generate-and-distribute pair into the server's
# storage directory; the network lanes of the PKCS#11 module suite present
# it as the mTLS client credential, because the unified server enforces
# authentication and the admin certificate is the only credential a fresh
# deployment holds.
publish_admin_credential() {
ADMIN_CERT_SRC="${STATE_DIR}/storage/admin-cert.pem"
ADMIN_KEY_SRC="${STATE_DIR}/storage/admin-key.pem"
ADMIN_CERT_DEST="$(dirname "$DEST")/admin-cert.pem"
ADMIN_KEY_DEST="$(dirname "$DEST")/admin-key.pem"
if [ -f "$ADMIN_CERT_SRC" ] && [ -f "$ADMIN_KEY_SRC" ]; then
	cp "$ADMIN_CERT_SRC" "$ADMIN_CERT_DEST"
	cp "$ADMIN_KEY_SRC" "$ADMIN_KEY_DEST"
	chmod 0600 "$ADMIN_KEY_DEST"
	echo "ensure-server-ca: published admin credential to ${ADMIN_CERT_DEST}"
else
	echo "ensure-server-ca: no admin credential under ${STATE_DIR}/storage; network lanes will run unauthenticated" >&2
fi
}


# With the qrdb storage backend the CA's certificates live inside the
# qrdb-backed store, not as files, so the file harvest below finds nothing.
# The canonical first-contact source is the public trust-bootstrap endpoint
# the daemon serves for exactly this purpose. It is fetched from a server
# verified against the anchors it persisted in its state volume, as
# open-server-barrier.sh verifies it: the bootstrap certificate, and the CA
# bundle the server writes beside it when it swaps that certificate for one
# its CA issued after the unseal (pkg/server/unified_tls.go
# persistUnifiedCABundle). Nothing is fetched unverified (DS-3769).
#
# Without the compose server the suites talk to the server
# start-test-xkmsd.sh started in this container, so its CA and admin
# credential are published instead, from its data directory and its loopback
# REST port. Docker's embedded DNS answers for the service only while its
# container runs.
if [ ! -d "$CERT_DIR" ] && ! getent hosts "$COMPOSE_SERVER_HOST" >/dev/null 2>&1; then
	echo "ensure-server-ca: ${COMPOSE_SERVER_HOST} is not running; publishing the CA of the server start-test-xkmsd.sh started"
	STATE_DIR="${XKMS_TEST_DATA_DIR:-/tmp/xkmsd-test}"
	CERT_DIR="${STATE_DIR}/storage/ca/certs"
	XKMS_SERVER_BOOTSTRAP_URL="https://localhost:${XKMS_TEST_REST_PORT:-18443}/v1/ca/bootstrap"
fi

if [ ! -d "$CERT_DIR" ]; then
	BOOTSTRAP_URL="${XKMS_SERVER_BOOTSTRAP_URL:-https://${COMPOSE_SERVER_HOST}:8443/v1/ca/bootstrap}"
	BOOTSTRAP_CERT="${STATE_DIR}/storage/unified-tls/cert.pem"
	SERVER_CA_BUNDLE="${STATE_DIR}/storage/unified-tls/ca-bundle.pem"
	anchors=$(mktemp)
	fetched=$(mktemp)
	trap 'rm -f "$anchors" "$fetched"' EXIT

	# trust -- write the anchors the server is verified against to $anchors,
	# read afresh for every attempt. Fails while the bootstrap certificate is
	# not readable.
	trust() {
		[ -r "$BOOTSTRAP_CERT" ] || return 1
		cat "$BOOTSTRAP_CERT" >"$anchors"
		if [ -r "$SERVER_CA_BUNDLE" ]; then
			cat "$SERVER_CA_BUNDLE" >>"$anchors"
		fi
	}

	for _ in $(seq 1 30); do
		if trust && curl -sf --cacert "$anchors" "$BOOTSTRAP_URL" -o "$fetched" &&
			grep -q -- "-----BEGIN CERTIFICATE-----" "$fetched"; then
			mkdir -p "$(dirname "$DEST")"
			cp "$fetched" "$DEST"
			echo "ensure-server-ca: fetched CA bundle from ${BOOTSTRAP_URL} to ${DEST}"
			publish_admin_credential
			exit 0
		fi
		sleep 2
	done
	if [ ! -r "$BOOTSTRAP_CERT" ]; then
		echo "ensure-server-ca: cannot read the server's bootstrap certificate ${BOOTSTRAP_CERT}; the CA is fetched only from a server it verifies" >&2
	else
		echo "ensure-server-ca: ${BOOTSTRAP_URL} served no CA bundle from a server the persisted anchors verify" >&2
	fi
	exit 1
fi

# Emit PEM on stdout for a certificate file in either encoding.
as_pem() {
	local file="$1"
	if grep -q -- "-----BEGIN CERTIFICATE-----" "$file" 2>/dev/null; then
		cat "$file"
	else
		openssl x509 -inform DER -in "$file" 2>/dev/null
	fi
}

subject_of() { openssl x509 -noout -subject 2>/dev/null; }

found=""
for cert in "$CERT_DIR"/*; do
	[ -f "$cert" ] || continue
	pem="$(as_pem "$cert")" || continue
	[ -n "$pem" ] || continue
	subject="$(printf '%s\n' "$pem" | openssl x509 -noout -subject 2>/dev/null || true)"
	issuer="$(printf '%s\n' "$pem" | openssl x509 -noout -issuer 2>/dev/null || true)"
	# Normalize the "subject=" / "issuer=" labels away before comparing.
	if [ -n "$subject" ] && [ "${subject#subject=}" = "${issuer#issuer=}" ]; then
		found="$pem"
		break
	fi
done

if [ -z "$found" ]; then
	echo "ensure-server-ca: no self-signed root certificate found under ${CERT_DIR}" >&2
	ls -l "$CERT_DIR" >&2 || true
	exit 1
fi

mkdir -p "$(dirname "$DEST")"
printf '%s\n' "$found" > "$DEST"
echo "ensure-server-ca: wrote $(printf '%s\n' "$found" | openssl x509 -noout -subject) to ${DEST}"


publish_admin_credential
