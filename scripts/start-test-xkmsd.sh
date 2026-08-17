#!/bin/bash
# start-test-xkmsd.sh — bring up an xkmsd instance for the PKCS#11 integration
# suites, and leave it running on a Unix socket the module can dial.
#
# The compose-based helper in the Makefile brings up an `xkms-server` service,
# but not every environment defines one (the shared devcontainer does not), and
# in that case `docker compose up` silently succeeds while starting nothing —
# the suite then fails at C_Initialize with CKR_DEVICE_ERROR and the cause is
# not obvious. This script is the fallback: if the socket is not already being
# served, it builds and starts xkmsd itself.
#
# It is idempotent. A socket that is already accepting connections is left
# alone, so running a second suite does not disturb the first.
#
# Usage:
#   start-test-xkmsd.sh [SOCKET_PATH]
# Environment:
#   XKMS_TEST_DATA_DIR   state directory      (default /tmp/xkmsd-test)
#   XKMS_TEST_LOG        server log file      (default /tmp/xkmsd-test.log)

set -euo pipefail

SOCKET="${1:-${XKMS_UNIX_SOCKET:-/var/run/xkms/xkms.sock}}"
DATA_DIR="${XKMS_TEST_DATA_DIR:-/tmp/xkmsd-test}"
LOG_FILE="${XKMS_TEST_LOG:-/tmp/xkmsd-test.log}"
CONFIG="${DATA_DIR}/xkmsd.yaml"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# A socket file can outlive the process that created it, so probe for a live
# listener rather than trusting the path to exist.
socket_is_live() {
	[ -S "$SOCKET" ] || return 1
	command -v nc >/dev/null 2>&1 || return 0
	nc -U -z "$SOCKET" 2>/dev/null
}

if socket_is_live; then
	echo "start-test-xkmsd: ${SOCKET} is already served; leaving it alone"
	exit 0
fi

echo "start-test-xkmsd: no listener on ${SOCKET}; starting one"
rm -f "$SOCKET"
mkdir -p "$(dirname "$SOCKET")" "${DATA_DIR}/data"

# The PKCS#11 suites only ever talk over the Unix socket, so the other
# protocols stay off: fewer moving parts, and no port collisions with a
# devcontainer that already publishes 8443/9443.
cat > "$CONFIG" <<EOF
server:
  host: "127.0.0.1"

protocols:
  unix: true
  rest: false
  grpc: false
  quic: false
  mcp: false

unix:
  enabled: true
  socket_path: ${SOCKET}
  socket_mode: 0666

tls:
  enabled: true
  server_cn: localhost

auth:
  enabled: true
  type: composite

barrier:
  enabled: true
  strategy: passphrase
  passphrase: pkcs11-conformance-test

ca:
  enabled: true
  identity:
    - subject:
        cn: "PKCS#11 Conformance Test Root CA"
        organization: "XKMS Tests"
      valid: 10
      keys:
        - algorithm: "ECDSA"
          ecc-curve: "P-256"
          key_type: "CA"
      keystore-type: "software"
      is-root: true
  selected-ca: 0
  default-validity-days: 365

logging:
  level: info
  format: json

storage:
  backend: file
  path: ${DATA_DIR}/data

default_backend: software

backends:
  software:
    enabled: true
    path: ${DATA_DIR}/data/keys

# The PKCS#11 module implements the full OASIS mechanism set, which includes the
# SHA-1 signature mechanisms the spec defines and legacy applications still use
# (CKM_SHA1_RSA_PKCS, CKM_ECDSA_SHA1). The module names the digest on the wire
# and the daemon performs it, so the conformance suite can only exercise those
# mechanisms against a daemon that has opted in: xkms refuses the
# collision-broken digests by default. This is the documented opt-in, scoped to
# a throwaway test daemon on a private Unix socket.
#
# The opt-in is a ceiling, not a floor: a FIPS run of the same suite ignores it
# (types.SetAllowWeakHashes refuses to loosen inside the validated module's
# boundary), withholds the non-approved mechanisms from C_GetMechanismList and
# refuses them outright, so nothing tries to use one.
crypto:
  allow_weak_hashes: true
EOF

BIN="${REPO_ROOT}/build/bin/xkmsd"
# Rebuild unconditionally. Building only when the binary is absent meant a test
# run served whatever daemon happened to be left over from an earlier session,
# so the suite silently exercised stale code and reported green for it. Four
# wrap/unwrap tests failed for exactly that reason and passed the moment the
# daemon was rebuilt -- a false RED is recoverable, a false GREEN is not.
# Go's build cache makes the no-change case cheap.
echo "start-test-xkmsd: building xkmsd"
mkdir -p "${REPO_ROOT}/build/bin"
# cgo is required: the USB/HID backends do not build without it.
( cd "$REPO_ROOT" && CGO_ENABLED=1 go build -buildvcs=false -o "$BIN" ./cmd/xkmsd )

# xkmsd has no insecure override; the config above is compliant (TLS from the
# embedded CA, composite jwt+mtls auth, auto-unsealing barrier). This instance serves a
# private Unix socket inside the test container over a throwaway data directory.
setsid nohup "$BIN" -config "$CONFIG" > "$LOG_FILE" 2>&1 < /dev/null &

for _ in $(seq 1 30); do
	if socket_is_live; then
		echo "start-test-xkmsd: ${SOCKET} is ready"
		exit 0
	fi
	sleep 1
done

echo "start-test-xkmsd: ${SOCKET} did not come up within 30s; server log follows" >&2
tail -30 "$LOG_FILE" >&2 || true
exit 1
