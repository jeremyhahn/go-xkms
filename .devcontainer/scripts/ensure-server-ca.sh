#!/bin/bash
# ensure-server-ca.sh — publish the compose xkms-server's root CA where the
# PKCS#11 integration suites expect to find it.
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

set -euo pipefail

STATE_DIR="${XKMS_SERVER_STATE_DIR:-/xkms-data}"
DEST="${XKMS_GRPC_TLS_CA:-/tmp/xkms/ca.crt}"
CERT_DIR="${STATE_DIR}/storage/ca/certs"

if [ ! -d "$CERT_DIR" ]; then
	echo "ensure-server-ca: ${CERT_DIR} does not exist; the compose xkms-server has not initialized its CA" >&2
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
