#!/bin/bash
# start-test-xkmsd.sh — make sure an xkmsd serves the Unix socket the PKCS#11
# integration suites dial, starting one in this container only when no server
# is there to serve it.
#
# The compose `xkms-server` service serves the socket through the xkms-socket
# volume it shares with the devcontainer. While that service runs, this script
# only waits for its socket: it never unlinks the socket or starts a second
# daemon on the path, because the suites must talk to the server the Makefile's
# devcontainer-server-wait step unsealed. Unlinking a live server's socket
# leaves that server listening on a deleted inode, so every later dial fails.
#
# When the service is not running (its image is not built, or
# XKMS_COMPOSE_SERVER=0), the script builds xkmsd and starts it the way an
# operator does: `xkmsd init` with the SO PIN in the environment, then the
# daemon, then an unseal through the sealed window by open-server-barrier.sh.
# No secret is written into the config; the loader refuses one.
#
# It is idempotent. A socket that is already accepting connections is left
# alone, so running a second suite does not disturb the first.
#
# Usage:
#   start-test-xkmsd.sh [SOCKET_PATH]
# Environment:
#   XKMS_TEST_DATA_DIR        state directory              (default /tmp/xkmsd-test)
#   XKMS_TEST_LOG             server log file              (default /tmp/xkmsd-test.log)
#   XKMS_TEST_REST_PORT       loopback sealed-window port  (default 18443)
#   XKMS_TEST_SO_PIN          SO PIN init makes the barrier passphrase
#   XKMS_TEST_BIN             where xkmsd is built         (default build/bin/xkmsd)
#   XKMS_COMPOSE_SERVER_HOST  compose server service name  (default xkms-server)
#   XKMS_SOCKET_WAIT          seconds to wait for a socket (default 30)

set -euo pipefail

SOCKET="${1:-${XKMS_UNIX_SOCKET:-/var/run/xkms/xkms.sock}}"
DATA_DIR="${XKMS_TEST_DATA_DIR:-/tmp/xkmsd-test}"
LOG_FILE="${XKMS_TEST_LOG:-/tmp/xkmsd-test.log}"
REST_PORT="${XKMS_TEST_REST_PORT:-18443}"
SO_PIN="${XKMS_TEST_SO_PIN:-pkcs11-conformance-test}"
COMPOSE_SERVER_HOST="${XKMS_COMPOSE_SERVER_HOST:-xkms-server}"
SOCKET_WAIT="${XKMS_SOCKET_WAIT:-30}"
CONFIG="${DATA_DIR}/xkmsd.yaml"
# xkmsd init writes the admin credential into the datastore path, and the
# daemon writes its bootstrap TLS certificate there on start.
# open-server-barrier.sh reads the certificate from <state dir>/storage, the
# layout the compose server keeps under /data.
STORAGE="${DATA_DIR}/storage"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${XKMS_TEST_BIN:-${REPO_ROOT}/build/bin/xkmsd}"
OPENER="${REPO_ROOT}/build/docker/devcontainer/scripts/open-server-barrier.sh"
PROBE="${REPO_ROOT}/scripts/socket-probe.sh"

# A socket file can outlive the process that created it, so probe for a live
# listener rather than trusting the path to exist.
socket_is_live() {
	[ -S "$SOCKET" ] || return 1
	sh "$PROBE" "$SOCKET" 2>/dev/null
}

# wait_for_socket polls for a live listener for up to SOCKET_WAIT seconds.
wait_for_socket() {
	local i
	for ((i = 0; i < SOCKET_WAIT; i++)); do
		socket_is_live && return 0
		sleep 1
	done
	socket_is_live
}

# socket_diagnostics prints what a client in this container sees at the
# socket, so a CI log names the cause instead of only the symptom.
socket_diagnostics() {
	echo "start-test-xkmsd: probing as $(id)" >&2
	ls -la "$(dirname "$SOCKET")" >&2 || true
	sh "$PROBE" "$SOCKET" >&2 || true
}

if socket_is_live; then
	echo "start-test-xkmsd: ${SOCKET} is already served; leaving it alone"
	exit 0
fi

# Docker's embedded DNS answers for a compose service only while its container
# runs, so a resolving name means the compose server owns the socket.
if getent hosts "$COMPOSE_SERVER_HOST" >/dev/null 2>&1; then
	echo "start-test-xkmsd: ${COMPOSE_SERVER_HOST} is running; waiting up to ${SOCKET_WAIT}s for ${SOCKET}"
	if wait_for_socket; then
		echo "start-test-xkmsd: ${SOCKET} is ready"
		exit 0
	fi
	echo "start-test-xkmsd: ${COMPOSE_SERVER_HOST} is running but ${SOCKET} accepts no connection; not replacing its socket" >&2
	socket_diagnostics
	exit 1
fi

echo "start-test-xkmsd: no server on ${SOCKET}; starting one"
rm -f "$SOCKET"
mkdir -p "$(dirname "$SOCKET")" "$DATA_DIR"

# The PKCS#11 suites only ever talk over the Unix socket, so gRPC, QUIC and
# MCP stay off: fewer moving parts. REST stays on because the barrier is opened
# over it, exactly as the compose server's is: qrdb's sealed window serves only
# the configured transports, and open-server-barrier.sh unseals over HTTPS and
# then waits for /health on the same port. rest_port is not 8443, so it never
# collides with a devcontainer that publishes 8443/9443, and the loopback host
# keeps it unreachable from outside this container.
cat > "$CONFIG" <<EOF
server:
  host: "localhost"
  rest_port: ${REST_PORT}

protocols:
  unix: true
  rest: true
  grpc: false
  quic: false
  mcp: false

unix:
  socket_path: ${SOCKET}

tls:
  enabled: true
  server_cn: localhost

auth:
  enabled: true
  type: composite

barrier:
  enabled: true
  strategy: passphrase

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

datastore:
  engine: file
  path: ${STORAGE}

default_backend: software

backends:
  software:
    enabled: true
    path: ${DATA_DIR}/keys

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
#
# allow_legacy_key_wrap re-admits RSA PKCS#1 v1.5 on Decrypt (CKM_RSA_PKCS,
# PKCS#11 v3.2 §6.1.6), which the OpenSSL suites use; kept in step with
# configs/xkmsd-integration.yaml.
crypto:
  allow_weak_hashes: true
  allow_legacy_key_wrap: true
EOF

# Rebuild unconditionally. Building only when the binary is absent meant a test
# run served whatever daemon happened to be left over from an earlier session,
# so the suite silently exercised stale code and reported green for it. Four
# wrap/unwrap tests failed for exactly that reason and passed the moment the
# daemon was rebuilt -- a false RED is recoverable, a false GREEN is not.
# Go's build cache makes the no-change case cheap.
echo "start-test-xkmsd: building xkmsd"
mkdir -p "$(dirname "$BIN")"
# cgo is required: the USB/HID backends do not build without it.
( cd "$REPO_ROOT" && CGO_ENABLED=1 go build -buildvcs=false -o "$BIN" ./cmd/xkmsd )

# A data directory without the admin credential was never fully initialized;
# it is throwaway test state, so start it over and run `xkmsd init` as an
# operator does before a first boot. The SO PIN becomes the barrier passphrase
# and travels in the environment, never in argv or the config.
if [ ! -f "${STORAGE}/admin-cert.pem" ]; then
	echo "start-test-xkmsd: initializing ${STORAGE}"
	rm -rf "$STORAGE" "${DATA_DIR}/keys"
	if ! XKMS_SO_PIN="$SO_PIN" "$BIN" init --config "$CONFIG" --data-dir "$STORAGE" \
		--hostname localhost --admin-factor mtls > "$LOG_FILE" 2>&1 < /dev/null; then
		echo "start-test-xkmsd: xkmsd init failed; its log follows" >&2
		tail -30 "$LOG_FILE" >&2 || true
		exit 1
	fi
fi

# xkmsd has no insecure override; the config above is compliant (TLS from the
# embedded CA, composite jwt+mtls auth, a passphrase barrier init sealed). This
# instance serves a private Unix socket inside the test container over a
# throwaway data directory. The daemon never sees the SO PIN.
setsid nohup env -u XKMS_SO_PIN "$BIN" -config "$CONFIG" >> "$LOG_FILE" 2>&1 < /dev/null &

# The daemon boots sealed and serves only its sealed window until the barrier
# is unsealed; the socket appears after that. The compose server is unsealed by
# the same helper (Makefile devcontainer-server-wait).
if ! XKMS_SERVER_WINDOW_URL="https://localhost:${REST_PORT}" \
	XKMS_SERVER_STATE_DIR="$DATA_DIR" \
	XKMS_SERVER_BARRIER_SECRET="$SO_PIN" \
	bash "$OPENER"; then
	echo "start-test-xkmsd: could not unseal the barrier; server log follows" >&2
	tail -30 "$LOG_FILE" >&2 || true
	exit 1
fi

if wait_for_socket; then
	echo "start-test-xkmsd: ${SOCKET} is ready"
	exit 0
fi

echo "start-test-xkmsd: ${SOCKET} did not come up within ${SOCKET_WAIT}s; server log follows" >&2
socket_diagnostics
tail -30 "$LOG_FILE" >&2 || true
exit 1
