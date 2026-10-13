#!/bin/bash
# open-server-barrier.sh — unseal the compose xkms-server through its sealed window.
#
# configs/xkmsd-integration.yaml enables a passphrase barrier, and a passphrase
# barrier never auto-unseals from configuration (go-xkms#653): the daemon boots
# sealed and serves only the sealed-window listener (pkg/server/sealed_window.go)
# on https://xkms-server:8443 until an operator unseals it. The Unix socket the
# suites dial does not exist until then, so this script is that operator, as
# test/integration/xkmsdtest.OpenBarrier is for the Go harnesses.
#
# It only ever unseals. The barrier is initialized by `xkmsd init` before the
# daemon first starts (the xkms-server command in .devcontainer/docker-compose.yml),
# with the SO PIN as its passphrase; the sealed window refuses initialization
# outright (HTTP 409). Any answer but 204 fails with the server's own message.
# An unsealed server is left alone.
#
# The window's TLS certificate is the bootstrap certificate the server persisted
# in its data volume, mounted read-only at $XKMS_SERVER_STATE_DIR. When that file
# is not readable by this container's user, the window is reached
# trust-on-first-use, the same ceremony ensure-server-ca.sh uses for this
# throwaway test deployment.
#
# Usage:
#   open-server-barrier.sh       # exit 0 once the barrier is open
# Environment:
#   XKMS_SERVER_STATE_DIR       read-only xkms-server state mount (default /xkms-data)
#   XKMS_SERVER_WINDOW_URL      sealed-window base URL (default https://xkms-server:8443)
#   XKMS_SERVER_BARRIER_SECRET  the server's test SO PIN, its barrier passphrase (required)

set -euo pipefail

STATE_DIR="${XKMS_SERVER_STATE_DIR:-/xkms-data}"
URL="${XKMS_SERVER_WINDOW_URL:-https://xkms-server:8443}"
CERT="${STATE_DIR}/storage/unified-tls/cert.pem"
ATTEMPTS=30

if [ -z "${XKMS_SERVER_BARRIER_SECRET:-}" ]; then
	echo "open-server-barrier: XKMS_SERVER_BARRIER_SECRET is not set" >&2
	exit 1
fi

# The unseal route takes {"secret": <bytes>}, which JSON carries as base64.
BODY="{\"secret\":\"$(printf '%s' "$XKMS_SERVER_BARRIER_SECRET" | base64 -w0)\"}"

tls_args() {
	if [ -r "$CERT" ]; then
		echo "--cacert $CERT"
	else
		echo "-k"
	fi
}

status=""
for _ in $(seq 1 "$ATTEMPTS"); do
	# shellcheck disable=SC2046
	if status=$(curl -sf $(tls_args) "${URL}/v1/barrier/status"); then
		break
	fi
	status=""
	sleep 2
done
if [ -z "$status" ]; then
	echo "open-server-barrier: ${URL}/v1/barrier/status did not answer" >&2
	exit 1
fi

if ! printf '%s' "$status" | grep -Eq '"sealed" *: *true'; then
	echo "open-server-barrier: barrier is already unsealed"
	exit 0
fi

reply=$(mktemp)
trap 'rm -f "$reply"' EXIT
# shellcheck disable=SC2046
code=$(curl -s $(tls_args) -o "$reply" -w '%{http_code}' -X POST \
	-H 'Content-Type: application/json' -d "$BODY" "${URL}/v1/barrier/unseal")
if [ "$code" != "204" ]; then
	echo "open-server-barrier: POST /v1/barrier/unseal returned HTTP ${code}: $(cat "$reply")" >&2
	if ! printf '%s' "$status" | grep -Eq '"initialized_at" *: *"[^"]+"'; then
		echo "open-server-barrier: the barrier was never initialized; xkmsd init did not complete on this volume (see the xkms-server log)" >&2
	fi
	exit 1
fi
echo "open-server-barrier: barrier unsealed"
